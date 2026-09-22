//! IVC over an append-only Merkle tree using Microsoft's Nova (`nova-snark`)
//! with transparent Spartan+IPA compression: each folding step appends one
//! leaf to an incremental (frontier-based) SHA-256 Merkle tree of fixed depth
//! `d` and outputs the updated root.
//!
//! The incremental-tree layout is the standard append-only construction
//! (Semaphore / Tornado-style): the state keeps, per level, the root of the
//! rightmost *filled* subtree (the "frontier"); appending the leaf at index
//! `i` walks the `d` levels once, hashing against either the frontier node
//! (when bit `j` of `i` is 1) or the constant zero-subtree root (when it is
//! 0, in which case the frontier at that level is refreshed). One append =
//! `d` SHA-256 hashes of 64-byte inputs (2 compression blocks each), fully
//! deterministic — no authentication-path witnesses.
//!
//! IVC state (`arity = 3 + 2d` field elements):
//!
//! ```text
//! z = [ index, root_hi, root_lo, frontier_0_hi, frontier_0_lo, ..., frontier_{d-1}_lo ]
//! ```
//!
//! Each 32-byte digest is packed big-endian into two 128-bit field elements
//! (`hi` = bytes 0..16, `lo` = bytes 16..32), so the packing constraints
//! double as range checks. The appended leaf is non-deterministic advice
//! carried by the per-step circuit instance: the statement proven is "there
//! exists a sequence of `n` leaves whose in-order append yields `root_n`"
//! (the leaves themselves are existentially quantified, as usual for this
//! kind of accumulator benchmark).

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
use sha2::{Digest, Sha256};

use crate::NovaCurve;
use bench_common::{IvcReport, MemProbe};

// --- Native incremental Merkle tree (reference implementation) ---

fn h2(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Roots of the all-zero-leaf subtrees, one per height: `zeros[0]` is the
/// empty leaf, `zeros[j] = H(zeros[j-1] || zeros[j-1])`. Length `depth + 1`
/// (`zeros[depth]` is the root of the empty tree).
pub fn zero_subtree_roots(depth: usize) -> Vec<[u8; 32]> {
    let mut zeros = Vec::with_capacity(depth + 1);
    zeros.push([0u8; 32]);
    for j in 1..=depth {
        let prev = zeros[j - 1];
        zeros.push(h2(&prev, &prev));
    }
    zeros
}

/// Append-only SHA-256 Merkle tree of fixed depth, tracking only the frontier
/// (one node per level) — the native mirror of the step circuit.
pub struct IncrementalMerkleTree {
    depth: usize,
    zeros: Vec<[u8; 32]>,
    frontier: Vec<[u8; 32]>,
    index: u64,
    root: [u8; 32],
}

impl IncrementalMerkleTree {
    pub fn new(depth: usize) -> Self {
        assert!((1..=64).contains(&depth), "depth must be in 1..=64");
        let zeros = zero_subtree_roots(depth);
        Self {
            depth,
            frontier: zeros[..depth].to_vec(),
            root: zeros[depth],
            zeros,
            index: 0,
        }
    }

    pub fn append(&mut self, leaf: [u8; 32]) {
        assert!(
            self.depth >= 64 || self.index < 1u64 << self.depth,
            "tree is full"
        );
        let mut cur = leaf;
        let mut idx = self.index;
        for j in 0..self.depth {
            if idx & 1 == 0 {
                self.frontier[j] = cur;
                cur = h2(&cur, &self.zeros[j]);
            } else {
                cur = h2(&self.frontier[j], &cur);
            }
            idx >>= 1;
        }
        self.root = cur;
        self.index += 1;
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn n_leaves(&self) -> u64 {
        self.index
    }

    /// The IVC state vector matching [`MerkleAppendCircuit`]'s layout.
    pub fn state_fields<F: PrimeField>(&self) -> Vec<F> {
        let mut z = Vec::with_capacity(3 + 2 * self.depth);
        z.push(F::from(self.index));
        let (hi, lo) = digest_halves::<F>(&self.root);
        z.push(hi);
        z.push(lo);
        for node in &self.frontier {
            let (hi, lo) = digest_halves::<F>(node);
            z.push(hi);
            z.push(lo);
        }
        z
    }
}

/// Deterministic pseudo-random leaf for step `i` of the benchmark.
pub fn bench_leaf(i: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"TransLog merkle leaf");
    h.update(i.to_le_bytes());
    h.finalize().into()
}

/// Pack a 32-byte digest big-endian into two 128-bit field elements.
pub fn digest_halves<F: PrimeField>(d: &[u8; 32]) -> (F, F) {
    let hi = u128::from_be_bytes(d[0..16].try_into().unwrap());
    let lo = u128::from_be_bytes(d[16..32].try_into().unwrap());
    (F::from_u128(hi), F::from_u128(lo))
}

fn f_to_u128<F: PrimeField>(f: &F) -> u128 {
    // Both supported cycles use a little-endian repr; state elements are
    // < 2^128 by construction (enforced in-circuit by the packing constraints).
    let repr = f.to_repr();
    let mut le = [0u8; 16];
    le.copy_from_slice(&repr.as_ref()[0..16]);
    u128::from_le_bytes(le)
}

// --- In-circuit gadget helpers ---

/// `out = b ? x : y`, one constraint: `(x - y) * b = out - y`.
fn mux<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    b: &Boolean,
    x: &Boolean,
    y: &Boolean,
) -> Result<Boolean, SynthesisError> {
    if let Boolean::Constant(c) = b {
        return Ok(if *c { x.clone() } else { y.clone() });
    }
    let value = match (b.get_value(), x.get_value(), y.get_value()) {
        (Some(bv), Some(xv), Some(yv)) => Some(if bv { xv } else { yv }),
        _ => None,
    };
    let out = AllocatedBit::alloc(cs.namespace(|| "bit"), value)?;
    let x_lc = x.lc(CS::one(), F::ONE);
    let y_lc = y.lc(CS::one(), F::ONE);
    let b_lc = b.lc(CS::one(), F::ONE);
    cs.enforce(
        || "select",
        |lc| lc + &x_lc - &y_lc,
        |lc| lc + &b_lc,
        |lc| lc + out.get_variable() - &y_lc,
    );
    Ok(Boolean::from(out))
}

/// Decompose a state element into 128 bits (MSB-first), enforcing that the
/// bits repack to the element — which also range-checks it to < 2^128.
fn unpack_128_be<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    num: &AllocatedNum<F>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let value = num.get_value().map(|f| f_to_u128(&f));
    let mut bits = Vec::with_capacity(128);
    for k in 0..128 {
        let bit = AllocatedBit::alloc(
            cs.namespace(|| format!("bit {k}")),
            value.map(|v| (v >> (127 - k)) & 1 == 1),
        )?;
        bits.push(Boolean::from(bit));
    }
    cs.enforce(
        || "packing",
        |mut lc| {
            for (k, b) in bits.iter().enumerate() {
                lc = lc + &b.lc(CS::one(), F::from_u128(1u128 << (127 - k)));
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
    );
    Ok(bits)
}

/// Pack 128 bits (MSB-first) into one field element.
fn pack_128_be<F: PrimeField, CS: ConstraintSystem<F>>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<F>, SynthesisError> {
    assert_eq!(bits.len(), 128);
    let value = bits
        .iter()
        .try_fold(0u128, |acc, b| b.get_value().map(|bit| (acc << 1) | bit as u128));
    let num = AllocatedNum::alloc(cs.namespace(|| "packed"), || {
        value
            .map(F::from_u128)
            .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "packing",
        |mut lc| {
            for (k, b) in bits.iter().enumerate() {
                lc = lc + &b.lc(CS::one(), F::from_u128(1u128 << (127 - k)));
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
    );
    Ok(num)
}

fn constant_digest_bits(d: &[u8; 32]) -> Vec<Boolean> {
    let mut bits = Vec::with_capacity(256);
    for byte in d {
        for j in (0..8).rev() {
            bits.push(Boolean::Constant((byte >> j) & 1 == 1));
        }
    }
    bits
}

// --- Step circuit ---

/// One IVC step: append `leaf` (non-deterministic advice, changes per step)
/// to the depth-`depth` incremental tree carried in the state, producing the
/// updated index, root and frontier. Costs `depth` in-circuit SHA-256 hashes
/// of 64-byte inputs.
#[derive(Clone, Debug)]
pub struct MerkleAppendCircuit<F: PrimeField> {
    depth: usize,
    leaf: [u8; 32],
    zeros: Vec<[u8; 32]>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> MerkleAppendCircuit<F> {
    pub fn new(depth: usize, leaf: [u8; 32]) -> Self {
        assert!((1..=64).contains(&depth), "depth must be in 1..=64");
        Self {
            depth,
            leaf,
            zeros: zero_subtree_roots(depth),
            _f: PhantomData,
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> StepCircuit<F> for MerkleAppendCircuit<F> {
    fn arity(&self) -> usize {
        3 + 2 * self.depth
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let d = self.depth;
        assert_eq!(z_in.len(), 3 + 2 * d);
        let index = &z_in[0];

        // Index bits, LSB-first; the packing constraint enforces index < 2^d.
        let index_val = index.get_value().map(|f| f_to_u128(&f));
        let mut index_bits = Vec::with_capacity(d);
        for j in 0..d {
            let bit = AllocatedBit::alloc(
                cs.namespace(|| format!("index bit {j}")),
                index_val.map(|v| (v >> j) & 1 == 1),
            )?;
            index_bits.push(Boolean::from(bit));
        }
        cs.enforce(
            || "index packing",
            |mut lc| {
                for (j, b) in index_bits.iter().enumerate() {
                    lc = lc + &b.lc(CS::one(), F::from_u128(1u128 << j));
                }
                lc
            },
            |lc| lc + CS::one(),
            |lc| lc + index.get_variable(),
        );

        // The appended leaf: free advice, only booleanity is enforced.
        let mut cur: Vec<Boolean> = Vec::with_capacity(256);
        for (i, byte) in self.leaf.iter().enumerate() {
            for j in (0..8).rev() {
                let bit = AllocatedBit::alloc(
                    cs.namespace(|| format!("leaf byte {i} bit {j}")),
                    Some((byte >> j) & 1 == 1),
                )?;
                cur.push(Boolean::from(bit));
            }
        }

        // Walk the levels: at level j, bit j of the index selects the sibling
        // (frontier node vs zero-subtree constant) and whether the frontier is
        // refreshed with the running hash.
        let mut new_frontier: Vec<AllocatedNum<F>> = Vec::with_capacity(2 * d);
        for j in 0..d {
            let mut frontier_bits =
                unpack_128_be(cs.namespace(|| format!("frontier {j} hi")), &z_in[3 + 2 * j])?;
            frontier_bits.extend(unpack_128_be(
                cs.namespace(|| format!("frontier {j} lo")),
                &z_in[4 + 2 * j],
            )?);
            let zeros_bits = constant_digest_bits(&self.zeros[j]);
            let b = &index_bits[j];

            // left = b ? frontier[j] : cur — which is also the new frontier[j].
            let mut left = Vec::with_capacity(256);
            for (k, (x, y)) in frontier_bits.iter().zip(cur.iter()).enumerate() {
                left.push(mux(
                    cs.namespace(|| format!("level {j} left bit {k}")),
                    b,
                    x,
                    y,
                )?);
            }
            // right = b ? cur : zeros[j]
            let mut right = Vec::with_capacity(256);
            for (k, (x, y)) in cur.iter().zip(zeros_bits.iter()).enumerate() {
                right.push(mux(
                    cs.namespace(|| format!("level {j} right bit {k}")),
                    b,
                    x,
                    y,
                )?);
            }

            new_frontier.push(pack_128_be(
                cs.namespace(|| format!("new frontier {j} hi")),
                &left[0..128],
            )?);
            new_frontier.push(pack_128_be(
                cs.namespace(|| format!("new frontier {j} lo")),
                &left[128..256],
            )?);

            let mut msg = left;
            msg.extend(right);
            cur = sha256(cs.namespace(|| format!("level {j} hash")), &msg)?;
        }

        let next_index = AllocatedNum::alloc(cs.namespace(|| "next index"), || {
            index
                .get_value()
                .map(|v| v + F::ONE)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        cs.enforce(
            || "increment index",
            |lc| lc + index.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + next_index.get_variable(),
        );

        let root_hi = pack_128_be(cs.namespace(|| "root hi"), &cur[0..128])?;
        let root_lo = pack_128_be(cs.namespace(|| "root lo"), &cur[128..256])?;

        let mut z_out = vec![next_index, root_hi, root_lo];
        z_out.extend(new_frontier);
        Ok(z_out)
    }
}

// --- Runner ---

pub struct MerkleIvcOutput {
    pub report: IvcReport,
    /// Root after the last append (cross-checked against the native tree).
    pub root: [u8; 32],
    pub n_leaves: u64,
}

fn run_merkle_ivc_generic<E1, E2>(
    label: &str,
    depth: usize,
    n_steps: usize,
    run_compression: bool,
    probe: MemProbe,
) -> Result<MerkleIvcOutput, Box<dyn std::error::Error>>
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
    type C<E1> = MerkleAppendCircuit<<E1 as Engine>::Scalar>;

    assert!(n_steps >= 1, "need at least one step");
    assert!(
        depth >= 64 || (n_steps as u128) <= 1u128 << depth,
        "more appends than the tree can hold"
    );

    let leaves: Vec<[u8; 32]> = (0..n_steps as u64).map(bench_leaf).collect();
    let circuits: Vec<C<E1>> = leaves
        .iter()
        .map(|leaf| MerkleAppendCircuit::new(depth, *leaf))
        .collect();

    let mut native = IncrementalMerkleTree::new(depth);
    let z0: Vec<E1::Scalar> = native.state_fields();

    // --- Setup: public parameters + (optional) Spartan pre-processing ---
    probe.reset_peak();
    let setup_start = Instant::now();
    let pp = PublicParams::<E1, E2, C<E1>>::setup(
        &circuits[0],
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
        eprintln!(
            "[nova+spartan-merkle/{label}] Spartan (transparent) keygen: {:?}",
            t.elapsed()
        );
        Some(keys)
    } else {
        None
    };

    let mut recursive_snark = RecursiveSNARK::<E1, E2, C<E1>>::new(&pp, &circuits[0], &z0)?;
    let setup_time = setup_start.elapsed();
    let setup_peak_mem = probe.peak();
    eprintln!(
        "[nova+spartan-merkle/{label}] depth {depth}, primary circuit: {} constraints, pp setup {:?}, total setup {:?}",
        pp.num_constraints().0,
        pp_setup,
        setup_time
    );

    // --- Folding steps (one leaf appended per step) ---
    probe.reset_peak();
    let mut step_times = Vec::with_capacity(n_steps);
    for circuit in &circuits {
        let start = Instant::now();
        recursive_snark.prove_step(&pp, circuit)?;
        step_times.push(start.elapsed());
    }
    let steps_peak_mem = probe.peak();

    // --- IVC verification + native cross-check ---
    let verify_start = Instant::now();
    let zn = recursive_snark.verify(&pp, n_steps, &z0)?;
    let mut verify_time = verify_start.elapsed();

    for leaf in &leaves {
        native.append(*leaf);
    }
    let expected: Vec<E1::Scalar> = native.state_fields();
    assert_eq!(
        zn, expected,
        "in-circuit Merkle append diverges from the native incremental tree"
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

    Ok(MerkleIvcOutput {
        report: IvcReport {
            backend: "Nova (microsoft) + Spartan — Merkle append".into(),
            config: format!(
                "{label} cycle, depth-{depth} incremental SHA-256 Merkle tree (frontier), \
                 Pedersen commitments, transparent Spartan+IPA compression"
            ),
            setup_time,
            setup_peak_mem,
            step_times,
            steps_peak_mem,
            finalize_time,
            finalize_peak_mem,
            verify_time: Some(verify_time),
        },
        root: native.root(),
        n_leaves: native.n_leaves(),
    })
}

/// Run the Merkle-append IVC on the selected curve cycle: `n_steps` appends
/// into a depth-`depth` tree, one leaf per folding step.
pub fn run_merkle_ivc(
    depth: usize,
    n_steps: usize,
    run_compression: bool,
    curve: NovaCurve,
    probe: MemProbe,
) -> Result<MerkleIvcOutput, Box<dyn std::error::Error>> {
    match curve {
        NovaCurve::Pasta => run_merkle_ivc_generic::<PallasEngine, VestaEngine>(
            "Pallas/Vesta",
            depth,
            n_steps,
            run_compression,
            probe,
        ),
        NovaCurve::Bn254 => run_merkle_ivc_generic::<Bn256EngineIPA, GrumpkinEngine>(
            "BN254/Grumpkin",
            depth,
            n_steps,
            run_compression,
            probe,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root of the classic full tree over zero-padded leaves — the semantic
    /// ground truth the incremental frontier construction must match.
    fn naive_root(depth: usize, leaves: &[[u8; 32]]) -> [u8; 32] {
        let size = 1usize << depth;
        assert!(leaves.len() <= size);
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        level.resize(size, [0u8; 32]);
        while level.len() > 1 {
            level = level.chunks(2).map(|p| h2(&p[0], &p[1])).collect();
        }
        level[0]
    }

    #[test]
    fn incremental_matches_naive_full_tree() {
        let depth = 3;
        let mut tree = IncrementalMerkleTree::new(depth);
        assert_eq!(tree.root(), naive_root(depth, &[]));
        let leaves: Vec<[u8; 32]> = (0..1u64 << depth).map(bench_leaf).collect();
        for i in 0..leaves.len() {
            tree.append(leaves[i]);
            assert_eq!(tree.root(), naive_root(depth, &leaves[..=i]), "after leaf {i}");
        }
    }

    #[test]
    fn merkle_ivc_bn254_compressed() -> Result<(), Box<dyn std::error::Error>> {
        let depth = 2;
        let n = 3;
        let out = run_merkle_ivc(depth, n, true, NovaCurve::Bn254, MemProbe::NONE)?;
        let leaves: Vec<[u8; 32]> = (0..n as u64).map(bench_leaf).collect();
        assert_eq!(out.root, naive_root(depth, &leaves));
        assert_eq!(out.n_leaves, n as u64);
        Ok(())
    }
}
