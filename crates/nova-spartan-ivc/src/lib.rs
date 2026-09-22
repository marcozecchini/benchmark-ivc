//! IVC over a SHA-256 chain using Microsoft's Nova (`nova-snark`) with a
//! transparent Spartan SNARK (Spartan + IPA-PC) as the final compression step.
//!
//! Like the Sonobe backend, the IVC state is 32 bytes encoded as 32 field
//! elements (one byte each); each step constrains `z_{i+1} = SHA-256(z_i)`
//! with the SHA-256 gadget shipped in nova-snark's frontend.
//!
//! The backend is generic over the curve cycle: both the Pasta cycle
//! (Pallas/Vesta) and BN254/Grumpkin are provided, so the fastest-proving
//! cycle can be selected empirically (`NovaCurve`). Spartan+IPA is fully
//! transparent — there is no trusted setup anywhere in this pipeline.

pub mod merkle;

use std::marker::PhantomData;
use std::time::Instant;

use ff::{PrimeField, PrimeFieldBits};
use nova_snark::{
    frontend::{
        gadgets::boolean::{AllocatedBit, Boolean},
        gadgets::sha256::sha256,
        num::AllocatedNum,
        ConstraintSystem, SynthesisError,
    },
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{Bn256EngineIPA, GrumpkinEngine, PallasEngine, VestaEngine},
    spartan::snark::RelaxedR1CSSNARK,
    traits::{circuit::StepCircuit, snark::RelaxedR1CSSNARKTrait, Engine},
};

use bench_common::{IvcReport, MemProbe};

/// SHA-256 chain step circuit: state = 32 bytes, one field element per byte.
#[derive(Clone, Debug, Default)]
pub struct Sha256ChainCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

fn byte_of<F: PrimeField>(f: &F) -> u8 {
    f.to_repr().as_ref()[0]
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for Sha256ChainCircuit<F> {
    fn arity(&self) -> usize {
        32
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert_eq!(z_in.len(), 32);

        // Decompose each state element into 8 bits (MSB-first, as the SHA-256
        // gadget expects), enforcing that the bits recompose to the element.
        let mut msg_bits: Vec<Boolean> = Vec::with_capacity(256);
        for (i, num) in z_in.iter().enumerate() {
            let byte_val = num.get_value().map(|v| byte_of(&v));
            let mut byte_bits = Vec::with_capacity(8);
            for j in (0..8).rev() {
                let bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("in byte {i} bit {j}")),
                    byte_val.map(|b| (b >> j) & 1 == 1),
                )?;
                byte_bits.push(Boolean::from(bit));
            }
            // byte_bits is MSB-first; packing coefficient of bit j is 2^j.
            cs.enforce(
                || format!("pack in byte {i}"),
                |mut lc| {
                    for (k, bit) in byte_bits.iter().enumerate() {
                        lc = lc + &bit.lc(CS::one(), F::from(1u64 << (7 - k)));
                    }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + num.get_variable(),
            );
            msg_bits.extend(byte_bits);
        }

        let digest_bits = sha256(cs.namespace(|| "sha256"), &msg_bits)?;
        assert_eq!(digest_bits.len(), 256);

        // Repack the 256 output bits (MSB-first per byte) into 32 field elements.
        let mut z_out = Vec::with_capacity(32);
        for (i, byte_bits) in digest_bits.chunks(8).enumerate() {
            let byte_val: Option<u8> = byte_bits.iter().enumerate().try_fold(0u8, |acc, (k, b)| {
                b.get_value().map(|bit| acc | ((bit as u8) << (7 - k)))
            });
            let num = AllocatedNum::alloc(cs.namespace(|| format!("out byte {i}")), || {
                byte_val
                    .map(|b| F::from(b as u64))
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            cs.enforce(
                || format!("pack out byte {i}"),
                |mut lc| {
                    for (k, bit) in byte_bits.iter().enumerate() {
                        lc = lc + &bit.lc(CS::one(), F::from(1u64 << (7 - k)));
                    }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + num.get_variable(),
            );
            z_out.push(num);
        }
        Ok(z_out)
    }
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

/// Which curve cycle to run Microsoft Nova on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NovaCurve {
    /// Pasta cycle (Pallas/Vesta) — nova-snark's classic native cycle.
    Pasta,
    /// BN254/Grumpkin via halo2curves.
    Bn254,
}

pub struct NovaIvcOutput {
    pub report: IvcReport,
    pub final_state: [u8; 32],
}

/// Generic runner over a curve cycle (E1, E2), with transparent Spartan+IPA
/// compression on both curves.
fn run_ivc_generic<E1, E2>(
    label: &str,
    input: [u8; 32],
    n_steps: usize,
    run_compression: bool,
    probe: MemProbe,
) -> Result<NovaIvcOutput, Box<dyn std::error::Error>>
where
    E1: Engine<Base = <E2 as Engine>::Scalar>,
    E2: Engine<Base = <E1 as Engine>::Scalar>,
    E1::Scalar: PrimeFieldBits,
    E2::Scalar: PrimeFieldBits,
    E1::GE: nova_snark::provider::traits::DlogGroup,
    E2::GE: nova_snark::provider::traits::DlogGroup,
    <E1::CE as nova_snark::traits::commitment::CommitmentEngineTrait<E1>>::CommitmentKey:
        nova_snark::provider::pedersen::CommitmentKeyExtTrait<E1>,
    <E2::CE as nova_snark::traits::commitment::CommitmentEngineTrait<E2>>::CommitmentKey:
        nova_snark::provider::pedersen::CommitmentKeyExtTrait<E2>,
{
    type EE1<E> = nova_snark::provider::ipa_pc::EvaluationEngine<E>;
    type C<E1> = Sha256ChainCircuit<<E1 as Engine>::Scalar>;

    assert!(n_steps >= 1, "need at least one step");
    let circuit = C::<E1>::default();
    let z0: Vec<E1::Scalar> = input.iter().map(|&b| E1::Scalar::from(b as u64)).collect();

    // --- Setup: public parameters + (optional) Spartan pre-processing ---
    probe.reset_peak();
    let setup_start = Instant::now();
    let pp = PublicParams::<E1, E2, C<E1>>::setup(
        &circuit,
        &*RelaxedR1CSSNARK::<E1, EE1<E1>>::ck_floor(),
        &*RelaxedR1CSSNARK::<E2, EE1<E2>>::ck_floor(),
    )?;
    let pp_setup = setup_start.elapsed();

    let compression_keys = if run_compression {
        let t = Instant::now();
        let keys = CompressedSNARK::<
            E1,
            E2,
            C<E1>,
            RelaxedR1CSSNARK<E1, EE1<E1>>,
            RelaxedR1CSSNARK<E2, EE1<E2>>,
        >::setup(&pp)?;
        eprintln!("[nova+spartan/{label}] Spartan (transparent) keygen: {:?}", t.elapsed());
        Some(keys)
    } else {
        None
    };

    let mut recursive_snark = RecursiveSNARK::<E1, E2, C<E1>>::new(&pp, &circuit, &z0)?;
    let setup_time = setup_start.elapsed();
    let setup_peak_mem = probe.peak();
    eprintln!(
        "[nova+spartan/{label}] primary circuit: {} constraints, pp setup {:?}, total setup {:?}",
        pp.num_constraints().0,
        pp_setup,
        setup_time
    );

    // --- Folding steps ---
    probe.reset_peak();
    let mut step_times = Vec::with_capacity(n_steps);
    for _ in 0..n_steps {
        let start = Instant::now();
        recursive_snark.prove_step(&pp, &circuit)?;
        step_times.push(start.elapsed());
    }
    let steps_peak_mem = probe.peak();

    // --- IVC verification + native cross-check ---
    let verify_start = Instant::now();
    let zn = recursive_snark.verify(&pp, n_steps, &z0)?;
    let mut verify_time = verify_start.elapsed();

    let expected = sha256_chain_native(input, n_steps);
    let mut final_state = [0u8; 32];
    for (i, f) in zn.iter().enumerate() {
        final_state[i] = byte_of(f);
    }
    assert_eq!(
        final_state, expected,
        "in-circuit SHA-256 chain diverges from native result"
    );

    // --- Final SNARK: Spartan (+IPA) compression ---
    let (finalize_time, finalize_peak_mem) = if let Some((pk, vk)) = compression_keys {
        probe.reset_peak();
        let start = Instant::now();
        let compressed = CompressedSNARK::prove(&pp, &pk, &recursive_snark)?;
        let finalize_time = start.elapsed();
        let finalize_peak_mem = probe.peak();

        let start = Instant::now();
        let zn2 = compressed.verify(&vk, n_steps, &z0)?;
        assert_eq!(zn2, zn, "compressed SNARK returned a different final state");
        verify_time += start.elapsed();
        (Some(finalize_time), finalize_peak_mem)
    } else {
        (None, None)
    };

    Ok(NovaIvcOutput {
        report: IvcReport {
            backend: "Nova (microsoft) + Spartan".into(),
            config: format!(
                "{label} cycle, Pedersen commitments, transparent Spartan+IPA compression"
            ),
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

/// Run the Microsoft-Nova IVC on the selected curve cycle.
pub fn run_ivc(
    input: [u8; 32],
    n_steps: usize,
    run_compression: bool,
    curve: NovaCurve,
    probe: MemProbe,
) -> Result<NovaIvcOutput, Box<dyn std::error::Error>> {
    match curve {
        NovaCurve::Pasta => run_ivc_generic::<PallasEngine, VestaEngine>(
            "Pallas/Vesta",
            input,
            n_steps,
            run_compression,
            probe,
        ),
        NovaCurve::Bn254 => run_ivc_generic::<Bn256EngineIPA, GrumpkinEngine>(
            "BN254/Grumpkin",
            input,
            n_steps,
            run_compression,
            probe,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_step_chain_pasta_compressed() -> Result<(), Box<dyn std::error::Error>> {
        let input = [7u8; 32];
        let out = run_ivc(input, 2, true, NovaCurve::Pasta, MemProbe::NONE)?;
        assert_eq!(out.final_state, sha256_chain_native(input, 2));
        Ok(())
    }

    #[test]
    fn two_step_chain_bn254_compressed() -> Result<(), Box<dyn std::error::Error>> {
        let input = [9u8; 32];
        let out = run_ivc(input, 2, true, NovaCurve::Bn254, MemProbe::NONE)?;
        assert_eq!(out.final_state, sha256_chain_native(input, 2));
        Ok(())
    }
}
