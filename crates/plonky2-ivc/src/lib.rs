//! IVC over a SHA-256 chain using Plonky2's native cyclic (STARK/FRI-based)
//! recursion on the Goldilocks 64-bit field with the Poseidon hasher.
//!
//! Each step proves: "the previous step's proof verifies, and the new state is
//! SHA-256 of the previous state". The last recursive proof is already the
//! final succinct proof — no separate compression stage is needed.
//!
//! Public input layout of the cyclic circuit:
//! - `[0..8)`   initial state (8 big-endian u32 words = the 32-byte input)
//! - `[8..16)`  current state (SHA-256 output of this step)
//! - `[16]`     step counter
//! - `[17..]`   verifier data for cyclic recursion

pub mod sha256;

use anyhow::{anyhow, ensure, Result};
use std::time::Instant;

use bench_common::{IvcReport, MemProbe};
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use sha256::{bytes_to_words, sha256_32bytes, sha256_chain_native};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <PoseidonGoldilocksConfig as GenericConfig<D>>::F;

struct StepTargets {
    condition: BoolTarget,
    inner_proof: ProofWithPublicInputsTarget<D>,
    verifier_data: VerifierCircuitTarget,
}

/// Build one layer of the step circuit. With `prev = None` the circuit only
/// contains the SHA-256 logic (used to seed the common-data fixed point);
/// with `prev = Some(cd)` it also conditionally verifies a proof of shape `cd`.
fn build_step_circuit(
    prev: Option<&CommonCircuitData<F, D>>,
) -> Result<(CircuitData<F, C, D>, Option<StepTargets>)> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let initial_state: [_; 8] = builder.add_virtual_public_input_arr();
    let step_input: [_; 8] = core::array::from_fn(|_| builder.add_virtual_target());
    let step_output = sha256_32bytes(&mut builder, &step_input);
    builder.register_public_inputs(&step_output);
    let counter = builder.add_virtual_public_input();

    let verifier_data = builder.add_verifier_data_public_inputs();

    let targets = if let Some(cd) = prev {
        let mut common_data = cd.clone();
        common_data.num_public_inputs = builder.num_public_inputs();

        let condition = builder.add_virtual_bool_target_safe();
        let inner_proof = builder.add_virtual_proof_with_pis(&common_data);
        let inner_pis = &inner_proof.public_inputs;

        // The whole chain shares one initial state.
        for j in 0..8 {
            builder.connect(initial_state[j], inner_pis[j]);
        }
        // Step input = inner output if recursing, else the initial state.
        for j in 0..8 {
            let selected = builder.select(condition, inner_pis[8 + j], initial_state[j]);
            builder.connect(step_input[j], selected);
        }
        // counter = inner_counter + 1 if recursing, else 1.
        let one = builder.one();
        let new_counter = builder.mul_add(condition.target, inner_pis[16], one);
        builder.connect(counter, new_counter);

        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_proof,
            &common_data,
        )?;
        Some(StepTargets {
            condition,
            inner_proof,
            verifier_data,
        })
    } else {
        // Seed layer: keep everything constrained, no recursion.
        for j in 0..8 {
            builder.connect(step_input[j], initial_state[j]);
        }
        let one = builder.one();
        builder.connect(counter, one);
        None
    };

    // `build()` panics if the passed common data doesn't match the built
    // circuit, which is expected during the fixed-point search; the caller
    // checks convergence via `CommonCircuitData` equality instead.
    let (data, _converged) = builder.try_build_with_options::<C>(true);
    Ok((data, targets))
}

/// Find the cyclic-recursion fixed point: a `CommonCircuitData` that describes
/// the very circuit which verifies proofs of that same shape.
fn build_cyclic_circuit() -> Result<(CircuitData<F, C, D>, StepTargets)> {
    let (seed, _) = build_step_circuit(None)?;
    let mut candidate = seed.common;
    for _ in 0..8 {
        let (data, targets) = build_step_circuit(Some(&candidate))?;
        if data.common == candidate {
            return Ok((data, targets.expect("recursive layer has targets")));
        }
        candidate = data.common.clone();
    }
    Err(anyhow!(
        "cyclic common data did not converge to a fixed point"
    ))
}

pub struct Plonky2IvcOutput {
    pub report: IvcReport,
    pub final_state: [u8; 32],
}

/// Run the full Plonky2 IVC: setup (fixed-point circuit build + base proof),
/// then `n_steps` recursive SHA-256 steps, then verification.
pub fn run_ivc(input: [u8; 32], n_steps: usize, probe: MemProbe) -> Result<Plonky2IvcOutput> {
    ensure!(n_steps >= 1, "need at least one step");

    // --- Setup ---
    probe.reset_peak();
    let setup_start = Instant::now();
    let (data, targets) = build_cyclic_circuit()?;
    let common = data.common.clone();
    let initial_words = bytes_to_words(input);
    let initial_pis = initial_words
        .iter()
        .enumerate()
        .map(|(i, &w)| (i, F::from_canonical_u32(w)))
        .collect();
    let base_proof = cyclic_base_proof(&common, &data.verifier_only, initial_pis);
    let setup_time = setup_start.elapsed();
    let setup_peak_mem = probe.peak();
    eprintln!(
        "[plonky2] circuit degree: 2^{} ({} public inputs), setup {:?}",
        common.degree_bits(),
        common.num_public_inputs,
        setup_time
    );

    // --- IVC steps ---
    probe.reset_peak();
    let mut step_times = Vec::with_capacity(n_steps);
    let mut proof = base_proof;
    for step in 0..n_steps {
        let start = Instant::now();
        let mut pw = PartialWitness::new();
        pw.set_bool_target(targets.condition, step > 0)?;
        pw.set_proof_with_pis_target(&targets.inner_proof, &proof)?;
        pw.set_verifier_data_target(&targets.verifier_data, &data.verifier_only)?;
        proof = data.prove(pw)?;
        step_times.push(start.elapsed());
    }
    let steps_peak_mem = probe.peak();

    // --- Verify final proof + cross-check against native SHA-256 chain ---
    probe.reset_peak();
    let verify_start = Instant::now();
    check_cyclic_proof_verifier_data(&proof, &data.verifier_only, &common)?;
    data.verify(proof.clone())?;
    let verify_time = verify_start.elapsed();

    ensure!(
        proof.public_inputs[16] == F::from_canonical_usize(n_steps),
        "counter mismatch"
    );
    let expected = sha256_chain_native(input, n_steps);
    let expected_words = bytes_to_words(expected);
    let mut final_state = [0u8; 32];
    for j in 0..8 {
        let word = proof.public_inputs[8 + j].to_canonical_u64();
        ensure!(
            word == expected_words[j] as u64,
            "in-circuit SHA-256 chain diverges from native result at word {j}"
        );
        final_state[4 * j..4 * j + 4].copy_from_slice(&(word as u32).to_be_bytes());
    }

    Ok(Plonky2IvcOutput {
        report: IvcReport {
            backend: "Plonky2 (cyclic STARK/FRI recursion)".into(),
            config: format!(
                "Goldilocks 64-bit field, Poseidon hasher, degree 2^{}",
                common.degree_bits()
            ),
            setup_time,
            setup_peak_mem,
            step_times,
            steps_peak_mem,
            finalize_time: None,
            finalize_peak_mem: None,
            verify_time: Some(verify_time),
        },
        final_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_step_chain() -> Result<()> {
        let input = [7u8; 32];
        let out = run_ivc(input, 3, MemProbe::NONE)?;
        assert_eq!(out.final_state, sha256_chain_native(input, 3));
        Ok(())
    }
}
