//! IVC over a SHA-256 chain using Sonobe's Nova + CycleFold folding on the
//! BN254/Grumpkin curve cycle.
//!
//! The IVC state is the 32-byte SHA-256 state, encoded as 32 field elements
//! (one byte each). Every folding step constrains `z_{i+1} = SHA-256(z_i)`
//! via the arkworks SHA-256 R1CS gadget. Folding (accumulation) cost is
//! measured per step; the final Decider (Groth16 + KZG over the compressed
//! decider circuit) is measured separately, as is its one-time setup.

#![allow(clippy::type_complexity)]

use std::marker::PhantomData;
use std::time::Instant;

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, convert::ToBitsGadget, eq::EqGadget, fields::fp::FpVar,
    uint8::UInt8, R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::{
        nova::{decider_eth::Decider as DeciderEth, Nova, PreprocessorParam},
        traits::CommittedInstanceOps,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, Error, FoldingScheme,
};

use bench_common::{IvcReport, MemProbe};

/// SHA-256 chain step circuit: state = 32 bytes, one field element per byte.
#[derive(Clone, Copy, Debug)]
pub struct Sha256ChainFCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> FCircuit<F> for Sha256ChainFCircuit<F> {
    type Params = ();
    type ExternalInputs = ();
    type ExternalInputsVar = ();

    fn new(_params: Self::Params) -> Result<Self, Error> {
        Ok(Self { _f: PhantomData })
    }

    fn state_len(&self) -> usize {
        32
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        _external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Reinterpret each state element as one byte: allocate the byte as a
        // witness and enforce that it recomposes to the state element. This is
        // sound (8 boolean constraints + 1 linear equality per byte) and far
        // cheaper than a full 254-bit decomposition of each element.
        let mut msg_bytes = Vec::with_capacity(32);
        for fp in &z_i {
            let byte_val = fp
                .value()
                .unwrap_or_default()
                .into_bigint()
                .to_bytes_le()[0];
            let byte = UInt8::new_witness(cs.clone(), || Ok(byte_val))?;
            let recomposed = Boolean::le_bits_to_fp(&byte.to_bits_le()?)?;
            recomposed.enforce_equal(fp)?;
            msg_bytes.push(byte);
        }

        let unit = UnitVar::default();
        let digest = Sha256Gadget::evaluate(&unit, &msg_bytes)?;

        // Digest bytes back to field elements (pure linear combinations).
        digest
            .0
            .iter()
            .map(|byte| Boolean::le_bits_to_fp(&byte.to_bits_le()?))
            .collect()
    }
}

type FC = Sha256ChainFCircuit<Fr>;
/// Nova + CycleFold over BN254/Grumpkin: KZG commitments on the primary curve,
/// Pedersen on the secondary, no hiding (fastest configuration).
type N = Nova<G1, G2, FC, KZG<'static, Bn254>, Pedersen<G2>, false>;
/// On-chain-style final compression: Groth16 + KZG over the decider circuit.
type D = DeciderEth<G1, G2, FC, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, N>;

pub fn state_to_bytes(state: &[Fr]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, fp) in state.iter().enumerate() {
        out[i] = fp.into_bigint().to_bytes_le()[0];
    }
    out
}

pub fn bytes_to_state(bytes: [u8; 32]) -> Vec<Fr> {
    bytes.iter().map(|&b| Fr::from(b as u64)).collect()
}

pub fn sha256_chain_native(input: [u8; 32], n_steps: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut state = input;
    for _ in 0..n_steps {
        let out = Sha256::digest(state);
        state.copy_from_slice(&out);
    }
    state
}

pub struct SonobeIvcOutput {
    pub report: IvcReport,
    pub final_state: [u8; 32],
}

/// Run the full Sonobe IVC: Nova preprocessing (+ optional Decider keygen),
/// `n_steps` folding steps, IVC verification, and (optionally) the final
/// Groth16 decider proof.
pub fn run_ivc(
    input: [u8; 32],
    n_steps: usize,
    run_decider: bool,
    probe: MemProbe,
) -> Result<SonobeIvcOutput, Box<dyn std::error::Error>> {
    assert!(n_steps >= 1, "need at least one step");
    let mut rng = rand::rngs::OsRng;

    let f_circuit = FC::new(())?;
    let z_0 = bytes_to_state(input);

    // --- Setup: Nova params + (optional) Decider params ---
    probe.reset_peak();
    let setup_start = Instant::now();
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let preprocessor_param = PreprocessorParam::new(poseidon_config, f_circuit);
    let nova_params = N::preprocess(&mut rng, &preprocessor_param)?;
    let nova_setup = setup_start.elapsed();

    let decider_params = if run_decider {
        let t = Instant::now();
        let params = D::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
        eprintln!("[sonobe] decider (Groth16+KZG) keygen: {:?}", t.elapsed());
        Some(params)
    } else {
        None
    };

    let mut nova = N::init(&nova_params, f_circuit, z_0.clone())?;
    let setup_time = setup_start.elapsed();
    let setup_peak_mem = probe.peak();
    eprintln!("[sonobe] Nova preprocess: {nova_setup:?}, total setup {setup_time:?}");

    // --- Folding steps ---
    probe.reset_peak();
    let mut step_times = Vec::with_capacity(n_steps);
    for _ in 0..n_steps {
        let start = Instant::now();
        nova.prove_step(rng, (), None)?;
        step_times.push(start.elapsed());
    }
    let steps_peak_mem = probe.peak();

    // --- IVC verification + native cross-check ---
    let verify_start = Instant::now();
    let ivc_proof = nova.ivc_proof();
    N::verify(nova_params.1.clone(), ivc_proof)?;
    let mut verify_time = verify_start.elapsed();

    let expected = sha256_chain_native(input, n_steps);
    let final_state = state_to_bytes(&nova.z_i);
    assert_eq!(
        final_state, expected,
        "in-circuit SHA-256 chain diverges from native result"
    );

    // --- Final SNARK (Decider) ---
    let (finalize_time, finalize_peak_mem) = if let Some((decider_pp, decider_vp)) = decider_params
    {
        probe.reset_peak();
        let start = Instant::now();
        let proof = D::prove(rng, decider_pp, nova.clone())?;
        let finalize_time = start.elapsed();
        let finalize_peak_mem = probe.peak();

        let start = Instant::now();
        let verified = D::verify(
            decider_vp,
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        )?;
        assert!(verified, "decider proof did not verify");
        verify_time += start.elapsed();
        (Some(finalize_time), finalize_peak_mem)
    } else {
        (None, None)
    };

    Ok(SonobeIvcOutput {
        report: IvcReport {
            backend: "Sonobe (Nova + CycleFold folding)".into(),
            config: "BN254/Grumpkin cycle, KZG + Pedersen commitments, Groth16 decider".into(),
            setup_time,
            setup_peak_mem,
            step_times,
            steps_peak_mem,
            finalize_time,
            finalize_peak_mem,
            verify_time: Some(verify_time),
        },
        final_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_step_chain_no_decider() -> Result<(), Box<dyn std::error::Error>> {
        let input = [7u8; 32];
        let out = run_ivc(input, 2, false, MemProbe::NONE)?;
        assert_eq!(out.final_state, sha256_chain_native(input, 2));
        Ok(())
    }

    /// Minimal decider sanity check with a trivial cubic circuit, to isolate
    /// environment issues from the SHA-256 circuit.
    #[test]
    fn cubic_decider() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Clone, Copy, Debug)]
        struct CubicFCircuit;
        impl FCircuit<Fr> for CubicFCircuit {
            type Params = ();
            type ExternalInputs = ();
            type ExternalInputsVar = ();
            fn new(_: ()) -> Result<Self, Error> {
                Ok(Self)
            }
            fn state_len(&self) -> usize {
                1
            }
            fn generate_step_constraints(
                &self,
                _cs: ConstraintSystemRef<Fr>,
                _i: usize,
                z_i: Vec<FpVar<Fr>>,
                _ext: (),
            ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
                Ok(vec![&z_i[0] * &z_i[0] * &z_i[0] + &z_i[0]])
            }
        }
        type NC = Nova<G1, G2, CubicFCircuit, KZG<'static, Bn254>, Pedersen<G2>, false>;
        type DC =
            DeciderEth<G1, G2, CubicFCircuit, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, NC>;

        let mut rng = rand::rngs::OsRng;
        let f_circuit = CubicFCircuit::new(())?;
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let preprocessor_param = PreprocessorParam::new(poseidon_config, f_circuit);
        let nova_params = NC::preprocess(&mut rng, &preprocessor_param)?;
        let (decider_pp, decider_vp) =
            DC::preprocess(&mut rng, (nova_params.clone(), f_circuit.state_len()))?;
        let mut nova = NC::init(&nova_params, f_circuit, vec![Fr::from(3u32)])?;
        nova.prove_step(rng, (), None)?;
        nova.prove_step(rng, (), None)?;
        let proof = DC::prove(rng, decider_pp, nova.clone())?;
        let verified = DC::verify(
            decider_vp,
            nova.i,
            nova.z_0.clone(),
            nova.z_i.clone(),
            &nova.U_i.get_commitments(),
            &nova.u_i.get_commitments(),
            &proof,
        )?;
        assert!(verified);
        Ok(())
    }
}
