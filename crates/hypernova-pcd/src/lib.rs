//! PCD (Proof-Carrying Data) over an n-ary SHA-256 tree, built on Sonobe's
//! HyperNova multifolding (MU = ARITY running accumulators, NU = 1 incoming
//! instance per step) on the BN254/Grumpkin cycle.
//!
//! Tree semantics (an n-ary Merkle tree over 32·ARITY-byte data blocks):
//! - every leaf node hashes its 32·ARITY-byte data block;
//! - every internal node hashes the ARITY children digests (32·ARITY bytes)
//!   and **merges the ARITY children accumulators into one**, in-circuit, via
//!   HyperNova's multifolding.
//!
//! The uniform step function for every node is `z' = SHA-256(z || ext)` with
//! `z` = 32 bytes (the left child's digest, or the block's first 32 bytes for
//! a leaf) and `ext` = 32·(ARITY−1) bytes (the other children's digests, or
//! the rest of the block). The node continues the LEFT child's chain and
//! folds the other ARITY−1 running accumulators via `prove_step`'s
//! `other_instances`; leaves fold trivial (dummy) accumulators, exactly like
//! Sonobe's own base step does.
//!
//! Rationale for n-ary: HyperNova folds MU instances with a SINGLE sum-check
//! (rounds and degree independent of MU), so a wider node amortizes the fixed
//! per-node recursion overhead over more data. The benchmark reports
//! throughput (data bytes proved per second) to compare arities fairly.
//!
//! Soundness caveat (documented in the README): the multifolding proves that
//! the merged accumulator attests *valid augmented-circuit instances*, but
//! Sonobe's augmented circuit binds the chain history (i, z_0, z_i) only for
//! the main accumulator, not for the extra folded ones. The benchmark can
//! natively verify each sibling's IVC proof before merging
//! (`verify_siblings`, on by default, measured separately).

#![allow(clippy::type_complexity)]

use core::borrow::Borrow;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr, G1Projective as G1};
use ark_crypto_primitives::crh::{
    sha256::constraints::{Sha256Gadget, UnitVar},
    CRHSchemeGadget,
};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_grumpkin::Projective as G2;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToBitsGadget,
    eq::EqGadget,
    fields::fp::FpVar,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use folding_schemes::{
    commitment::{kzg::KZG, pedersen::Pedersen},
    folding::hypernova::{decider_eth::Decider as DeciderEth, HyperNova},
    folding::nova::PreprocessorParam,
    folding::traits::CommittedInstanceOps,
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
    Decider, Error, FoldingScheme, MultiFolding,
};

use bench_common::{fmt_bytes, fmt_duration, MemProbe};

/// External inputs of a node: the digests of the ARITY−1 non-leftmost
/// children (or the tail of the leaf's data block), one byte per element.
#[derive(Clone, Debug)]
pub struct ExtDigests<F: PrimeField, const ARITY: usize>(pub Vec<F>);

impl<F: PrimeField, const ARITY: usize> Default for ExtDigests<F, ARITY> {
    fn default() -> Self {
        Self(vec![F::zero(); 32 * (ARITY - 1)])
    }
}

#[derive(Clone, Debug)]
pub struct ExtDigestsVar<F: PrimeField>(pub Vec<FpVar<F>>);

impl<F: PrimeField, const ARITY: usize> AllocVar<ExtDigests<F, ARITY>, F> for ExtDigestsVar<F> {
    fn new_variable<T: Borrow<ExtDigests<F, ARITY>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let binding = f()?;
        let values = binding.borrow();
        let vars = values
            .0
            .iter()
            .map(|v| FpVar::new_variable(cs.clone(), || Ok(*v), mode))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ExtDigestsVar(vars))
    }
}

/// Uniform PCD node circuit: `z' = SHA-256(z || ext)`, 32·ARITY bytes hashed
/// per node. State and external inputs hold one byte per field element.
#[derive(Clone, Copy, Debug)]
pub struct Sha256MergeFCircuit<F: PrimeField, const ARITY: usize> {
    _f: PhantomData<F>,
}

impl<F: PrimeField, const ARITY: usize> FCircuit<F> for Sha256MergeFCircuit<F, ARITY> {
    type Params = ();
    type ExternalInputs = ExtDigests<F, ARITY>;
    type ExternalInputsVar = ExtDigestsVar<F>;

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
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        assert_eq!(external_inputs.0.len(), 32 * (ARITY - 1));
        // Reinterpret the state+external elements as bytes (byte witness +
        // linear equality; see the sonobe-ivc crate for the technique).
        let mut msg_bytes = Vec::with_capacity(32 * ARITY);
        for fp in z_i.iter().chain(external_inputs.0.iter()) {
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

        digest
            .0
            .iter()
            .map(|byte| Boolean::le_bits_to_fp(&byte.to_bits_le()?))
            .collect()
    }
}

type Fc<const A: usize> = Sha256MergeFCircuit<Fr, A>;
/// HyperNova with MU = ARITY (own running accumulator + ARITY−1 siblings) and
/// NU = 1 (the step's own incoming instance).
pub type Hn<const A: usize> = HnB<A, A>;
/// Bucketed variant: the circuit hashes 32*W bytes per node while the folding
/// merges MU accumulators (W >= MU; merge inputs are zero-padded to 32*W).
pub type HnB<const W: usize, const MU: usize> =
    HyperNova<G1, G2, Fc<W>, KZG<'static, Bn254>, Pedersen<G2>, MU, 1, false>;
type Dec<const A: usize> = DecB<A, A>;
type DecB<const W: usize, const MU: usize> =
    DeciderEth<G1, G2, Fc<W>, KZG<'static, Bn254>, Pedersen<G2>, Groth16<Bn254>, HnB<W, MU>, MU, 1>;
type RunningAcc<const A: usize> = RunningAccB<A, A>;
type RunningAccB<const W: usize, const MU: usize> =
    <HnB<W, MU> as MultiFolding<G1, G2, Fc<W>>>::RunningInstance;

pub fn bytes_to_state(bytes: &[u8]) -> Vec<Fr> {
    bytes.iter().map(|&b| Fr::from(b as u64)).collect()
}

pub fn state_to_bytes(state: &[Fr]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, fp) in state.iter().enumerate() {
        out[i] = fp.into_bigint().to_bytes_le()[0];
    }
    out
}

fn sha256_native(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Native Merkle root with bucket width w_words (32*w-byte blocks/hash
/// inputs) and fan-in mu; internal inputs are zero-padded to 32*w bytes.
pub fn merkle_root_native_bucketed(w_words: usize, mu: usize, blocks: &[Vec<u8>]) -> [u8; 32] {
    let mut layer: Vec<[u8; 32]> = blocks.iter().map(|b| sha256_native(b)).collect();
    while layer.len() > 1 {
        layer = layer
            .chunks(mu)
            .map(|group| {
                let mut buf: Vec<u8> = group.iter().flatten().copied().collect();
                buf.resize(32 * w_words, 0u8);
                sha256_native(&buf)
            })
            .collect();
    }
    layer[0]
}

/// Native n-ary Merkle root over 32·arity-byte leaf blocks.
pub fn merkle_root_native(arity: usize, blocks: &[Vec<u8>]) -> [u8; 32] {
    let mut layer: Vec<[u8; 32]> = blocks.iter().map(|b| sha256_native(b)).collect();
    while layer.len() > 1 {
        layer = layer
            .chunks(arity)
            .map(|group| {
                let buf: Vec<u8> = group.iter().flatten().copied().collect();
                sha256_native(&buf)
            })
            .collect();
    }
    layer[0]
}

/// Deterministic 32·arity-byte data blocks for the benchmark.
pub fn make_blocks(arity: usize, n_leaves: usize) -> Vec<Vec<u8>> {
    (0..n_leaves)
        .map(|i| {
            (0..32 * arity)
                .map(|j| (i as u8).wrapping_mul(31).wrapping_add(j as u8).wrapping_add(1))
                .collect()
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct PcdNodeTiming {
    /// 0 = leaf-hash nodes; k = k-th merge layer.
    pub level: usize,
    /// Time of the `prove_step` (folding + augmented-circuit witness).
    pub prove_time: Duration,
    /// Native IVC verification of the ARITY−1 siblings before merging.
    pub sibling_check: Option<Duration>,
    /// Retries due to the defensive panic guard around the prover.
    pub retries: usize,
}

#[derive(Debug, Clone)]
pub struct PcdReport {
    pub arity: usize,
    /// Bytes hashed per node (32 * W); == 32 * arity when not bucketed.
    pub bucket_bytes: usize,
    pub depth: usize,
    pub data_bytes: usize,
    pub setup_time: Duration,
    pub setup_peak_mem: Option<usize>,
    pub nodes: Vec<PcdNodeTiming>,
    pub tree_peak_mem: Option<usize>,
    pub decider_time: Option<Duration>,
    pub decider_peak_mem: Option<usize>,
    pub verify_time: Duration,
    pub root_digest: [u8; 32],
}

impl PcdReport {
    pub fn total_prove_time(&self) -> Duration {
        self.nodes.iter().map(|n| n.prove_time).sum()
    }
    /// Data bytes proved per second of tree proving (setup/decider excluded).
    pub fn throughput_bps(&self) -> f64 {
        self.data_bytes as f64 / self.total_prove_time().as_secs_f64().max(1e-9)
    }
}

pub struct PcdOptions {
    /// Tree depth: `arity^depth` leaves.
    pub depth: usize,
    pub run_decider: bool,
    pub verify_siblings: bool,
}

/// Defensive guard: snapshot the accumulator, catch a prover panic, restore
/// and retry with fresh randomness (never observed to trigger since the
/// decider dummy-shape fix, but kept as insurance for MU > 1 paths that
/// upstream does not test).
fn prove_step_with_retry<const W: usize, const MU: usize>(
    hn: &mut HnB<W, MU>,
    ext: ExtDigests<Fr, W>,
    other: Vec<RunningAccB<W, MU>>,
    label: &str,
) -> Result<(Duration, usize), Error> {
    const MAX_ATTEMPTS: usize = 4;
    for attempt in 0..MAX_ATTEMPTS {
        let snapshot = hn.clone();
        let start = Instant::now();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hn.prove_step(
                &mut rand::rngs::OsRng,
                ext.clone(),
                Some((other.clone(), vec![])),
            )
        }));
        match result {
            Ok(Ok(())) => return Ok((start.elapsed(), attempt)),
            Ok(Err(e)) => return Err(e),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "<non-string panic>".into());
                eprintln!(
                    "[hypernova-pcd] prover panic at {label} (attempt {}): {msg} — retrying",
                    attempt + 1
                );
                *hn = snapshot;
            }
        }
    }
    Err(Error::Other(format!(
        "prove_step at {label} kept panicking after {MAX_ATTEMPTS} attempts"
    )))
}

/// Build the PCD tree bottom-up, measuring every node.
pub fn run_pcd2<const W: usize, const MU: usize>(
    opts: &PcdOptions,
    probe: MemProbe,
) -> Result<PcdReport, Error> {
    assert!(W >= MU, "bucket width W must be >= folding arity MU");
    assert!(MU >= 2, "arity must be >= 2");
    assert!(opts.depth >= 1, "depth must be >= 1");
    let n_leaves = MU.pow(opts.depth as u32);
    let mut rng = rand::rngs::OsRng;
    let f_circuit = Fc::<W>::new(())?;

    // --- Setup ---
    probe.reset_peak();
    let setup_start = Instant::now();
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let prep_param = PreprocessorParam::new(poseidon_config, f_circuit);
    let params = HnB::<W, MU>::preprocess(&mut rng, &prep_param)?;
    // Template instance: its (U_i, W_i) at i=0 is the trivial (dummy)
    // accumulator that leaf steps fold (MU = ARITY requires ARITY−1 extras).
    let template = HnB::<W, MU>::init(&params, f_circuit, vec![Fr::from(0u64); 32])?;
    let trivial_acc = (template.U_i.clone(), template.W_i.clone());
    let setup_time = setup_start.elapsed();
    let setup_peak_mem = probe.peak();
    eprintln!(
        "[hypernova-pcd] arity {MU} bucket {}B: setup (preprocess + trivial accumulator): {setup_time:?}", 32 * W
    );

    // --- Tree construction, bottom-up ---
    let blocks = make_blocks(W, n_leaves);
    probe.reset_peak();
    let mut nodes: Vec<PcdNodeTiming> = Vec::new();

    // Level 0: leaf-hash nodes, one fresh chain per leaf.
    let mut layer: Vec<HnB<W, MU>> = Vec::with_capacity(n_leaves);
    for (leaf_idx, block) in blocks.iter().enumerate() {
        let init_start = Instant::now();
        let mut hn = HnB::<W, MU>::init(&params, f_circuit, bytes_to_state(&block[..32]))?;
        let init_time = init_start.elapsed();
        let ext = ExtDigests::<Fr, W>(bytes_to_state(&block[32..]));
        let (prove_time, retries) = prove_step_with_retry(
            &mut hn,
            ext,
            vec![trivial_acc.clone(); MU - 1],
            &format!("leaf {leaf_idx}"),
        )?;
        nodes.push(PcdNodeTiming {
            level: 0,
            prove_time: init_time + prove_time,
            sibling_check: None,
            retries,
        });
        layer.push(hn);
    }

    // Merge layers: fold the ARITY−1 sibling accumulators into the left chain.
    let mut level = 1usize;
    while layer.len() > 1 {
        assert_eq!(layer.len() % MU, 0, "tree must be a full MU-ary tree");
        let mut next: Vec<HnB<W, MU>> = Vec::with_capacity(layer.len() / MU);
        let mut it = layer.into_iter();
        loop {
            let Some(mut left) = it.next() else { break };
            let siblings: Vec<HnB<W, MU>> = (1..MU).map(|_| it.next().unwrap()).collect();

            let sibling_check = if opts.verify_siblings {
                let t = Instant::now();
                for s in &siblings {
                    HnB::<W, MU>::verify(params.1.clone(), s.ivc_proof())?;
                }
                Some(t.elapsed())
            } else {
                None
            };

            let mut ext_v: Vec<Fr> = siblings.iter().flat_map(|s| s.z_i.clone()).collect();
            ext_v.resize(32 * (W - 1), Fr::from(0u64));
            let ext = ExtDigests::<Fr, W>(ext_v);
            let other: Vec<RunningAccB<W, MU>> = siblings
                .iter()
                .map(|s| (s.U_i.clone(), s.W_i.clone()))
                .collect();
            let (prove_time, retries) =
                prove_step_with_retry(&mut left, ext, other, &format!("merge level {level}"))?;
            nodes.push(PcdNodeTiming {
                level,
                prove_time,
                sibling_check,
                retries,
            });
            next.push(left);
        }
        layer = next;
        level += 1;
    }
    let tree_peak_mem = probe.peak();
    let root = layer.pop().expect("root exists");

    // --- Root IVC verification + native cross-check ---
    let verify_start = Instant::now();
    HnB::<W, MU>::verify(params.1.clone(), root.ivc_proof())?;
    let mut verify_time = verify_start.elapsed();

    let root_digest = state_to_bytes(&root.z_i);
    let expected = merkle_root_native_bucketed(W, MU, &blocks);
    assert_eq!(
        root_digest, expected,
        "in-circuit PCD root diverges from native Merkle root"
    );

    // --- Optional decider (Groth16 + KZG) on the root accumulator ---
    let (decider_time, decider_peak_mem) = if opts.run_decider {
        probe.reset_peak();
        let t = Instant::now();
        let (decider_pp, decider_vp) =
            DecB::<W, MU>::preprocess(&mut rng, (params.clone(), f_circuit.state_len()))?;
        eprintln!("[hypernova-pcd] decider keygen: {:?}", t.elapsed());
        let start = Instant::now();
        let proof = DecB::<W, MU>::prove(rng, decider_pp, root.clone())?;
        let decider_time = start.elapsed();
        let decider_peak_mem = probe.peak();

        let start = Instant::now();
        let verified = DecB::<W, MU>::verify(
            decider_vp,
            root.i,
            root.z_0.clone(),
            root.z_i.clone(),
            &root.U_i.get_commitments(),
            &root.u_i.get_commitments(),
            &proof,
        )?;
        assert!(verified, "decider proof did not verify");
        verify_time += start.elapsed();
        (Some(decider_time), decider_peak_mem)
    } else {
        (None, None)
    };

    Ok(PcdReport {
        arity: MU,
        bucket_bytes: 32 * W,
        depth: opts.depth,
        data_bytes: 32 * W * n_leaves,
        setup_time,
        setup_peak_mem,
        nodes,
        tree_peak_mem,
        decider_time,
        decider_peak_mem,
        verify_time,
        root_digest,
    })
}



/// Non-bucketed entry point (bucket width == folding arity).
pub fn run_pcd<const ARITY: usize>(opts: &PcdOptions, probe: MemProbe) -> Result<PcdReport, Error> {
    run_pcd2::<ARITY, ARITY>(opts, probe)
}

// --------------------------------------------------------------------------
// Reckle-style single-leaf update benchmark
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UpdatePathTiming {
    /// 0 = the re-proved leaf; k = the k-th merge on the leaf-to-root path.
    pub level: usize,
    pub prove_time: Duration,
    pub retries: usize,
}

#[derive(Debug, Clone)]
pub struct UpdateReport {
    pub arity: usize,
    /// Bytes hashed per node (32 * W).
    pub bucket_bytes: usize,
    pub depth: usize,
    pub n_leaves: usize,
    /// Cryptographic setup (preprocess + trivial accumulator).
    pub setup_time: Duration,
    /// Initial tree construction via the identical-leaves clone trick
    /// (1 leaf + depth merges instead of the full tree).
    pub initial_tree_time: Duration,
    pub setup_peak_mem: Option<usize>,
    /// The measured single-leaf update: leaf re-prove + path merges.
    pub path: Vec<UpdatePathTiming>,
    pub update_peak_mem: Option<usize>,
    pub decider_time: Option<Duration>,
    pub decider_peak_mem: Option<usize>,
    pub verify_time: Duration,
    pub new_root: [u8; 32],
}

impl UpdateReport {
    pub fn total_update_time(&self) -> Duration {
        self.path.iter().map(|p| p.prove_time).sum()
    }
}

pub struct UpdateOptions {
    pub n_leaves: usize,
    pub run_decider: bool,
}

fn exact_log(arity: usize, n: usize) -> usize {
    let (mut d, mut m) = (0usize, 1usize);
    while m < n {
        m *= arity;
        d += 1;
    }
    assert_eq!(m, n, "n_leaves must be an exact power of the arity");
    d
}

type HnParams<const W: usize, const MU: usize> = (
    <HnB<W, MU> as FoldingScheme<G1, G2, Fc<W>>>::ProverParam,
    <HnB<W, MU> as FoldingScheme<G1, G2, Fc<W>>>::VerifierParam,
);

/// A pre-existing ARITY-ary tree over identical leaf blocks, represented by
/// one accumulator per level (all same-level subtrees are identical, so one
/// representative — cloned across siblings — is a valid accumulator tree).
pub struct IdenticalTree<const W: usize, const MU: usize> {
    pub params: HnParams<W, MU>,
    pub trivial_acc: RunningAccB<W, MU>,
    /// rep[k] = accumulator chain attesting the (identical) depth-k subtree.
    pub rep: Vec<HnB<W, MU>>,
    /// d_old[k] = native digest of the depth-k subtree.
    pub d_old: Vec<[u8; 32]>,
    pub old_block: Vec<u8>,
    pub setup_time: Duration,
    pub build_time: Duration,
}

fn build_identical_tree<const W: usize, const MU: usize>(depth: usize) -> Result<IdenticalTree<W, MU>, Error> {
    let mut rng = rand::rngs::OsRng;
    let f_circuit = Fc::<W>::new(())?;

    let setup_start = Instant::now();
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let prep_param = PreprocessorParam::new(poseidon_config, f_circuit);
    let params = HnB::<W, MU>::preprocess(&mut rng, &prep_param)?;
    let template = HnB::<W, MU>::init(&params, f_circuit, vec![Fr::from(0u64); 32])?;
    let trivial_acc = (template.U_i.clone(), template.W_i.clone());
    let setup_time = setup_start.elapsed();

    let old_block: Vec<u8> = (0..32 * W).map(|j| 0xA0u8.wrapping_add(j as u8)).collect();
    let mut d_old: Vec<[u8; 32]> = vec![sha256_native(&old_block)];
    for _ in 1..=depth {
        let mut buf: Vec<u8> = d_old.last().unwrap().repeat(MU);
        buf.resize(32 * W, 0u8);
        d_old.push(sha256_native(&buf));
    }

    let build_start = Instant::now();
    let mut rep: Vec<HnB<W, MU>> = Vec::with_capacity(depth + 1);
    {
        let mut leaf = HnB::<W, MU>::init(&params, f_circuit, bytes_to_state(&old_block[..32]))?;
        let ext = ExtDigests::<Fr, W>(bytes_to_state(&old_block[32..]));
        prove_step_with_retry(&mut leaf, ext, vec![trivial_acc.clone(); MU - 1], "rep leaf")?;
        assert_eq!(state_to_bytes(&leaf.z_i), d_old[0]);
        rep.push(leaf);
    }
    for k in 1..=depth {
        let child = &rep[k - 1];
        let sib_acc = (child.U_i.clone(), child.W_i.clone());
        let sib_digest = child.z_i.clone();
        let mut node = child.clone();
        let mut ext_v: Vec<Fr> = std::iter::repeat(sib_digest).take(MU - 1).flatten().collect();
        ext_v.resize(32 * (W - 1), Fr::from(0u64));
        let ext = ExtDigests::<Fr, W>(ext_v);
        prove_step_with_retry(
            &mut node,
            ext,
            vec![sib_acc; MU - 1],
            &format!("rep level {k}"),
        )?;
        assert_eq!(state_to_bytes(&node.z_i), d_old[k]);
        rep.push(node);
    }
    HnB::<W, MU>::verify(params.1.clone(), rep[depth].ivc_proof())?;
    let build_time = build_start.elapsed();

    Ok(IdenticalTree {
        params,
        trivial_acc,
        rep,
        d_old,
        old_block,
        setup_time,
        build_time,
    })
}

/// Reckle-style benchmark: single-leaf update in an ARITY-ary tree of
/// `n_leaves` leaves. The pre-existing tree uses identical leaf blocks, so
/// one representative accumulator per level (cloned across siblings) is a
/// valid accumulator tree and the native Merkle cross-check stays exact.
/// The measured update (leaf re-prove + log_ARITY(n) path merges folding the
/// stored sibling accumulators) is real proving end to end.
pub fn run_update2<const W: usize, const MU: usize>(
    opts: &UpdateOptions,
    probe: MemProbe,
) -> Result<UpdateReport, Error> {
    assert!(W >= MU);
    let depth = exact_log(MU, opts.n_leaves);
    assert!(depth >= 1);
    let mut rng = rand::rngs::OsRng;
    let f_circuit = Fc::<W>::new(())?;

    // --- Setup + initial tree via the clone trick ---
    probe.reset_peak();
    let tree = build_identical_tree::<W, MU>(depth)?;
    let IdenticalTree {
        params,
        trivial_acc,
        rep,
        d_old,
        old_block: _,
        setup_time,
        build_time: initial_tree_time,
    } = tree;
    let setup_peak_mem = probe.peak();
    eprintln!(
        "[hypernova-pcd/update] arity {MU} bucket {}B: setup {setup_time:?}, initial tree (clone trick, {} steps) {initial_tree_time:?}",
        32 * W,
        depth + 1
    );

    // --- The measured update: new block in leaf 0, re-prove the path ---
    let new_block: Vec<u8> = (0..32 * W).map(|j| 0x35u8.wrapping_mul(j as u8 + 7)).collect();
    probe.reset_peak();
    let mut path: Vec<UpdatePathTiming> = Vec::with_capacity(depth + 1);

    let leaf_start = Instant::now();
    let mut cur = HnB::<W, MU>::init(&params, f_circuit, bytes_to_state(&new_block[..32]))?;
    let init_time = leaf_start.elapsed();
    let ext = ExtDigests::<Fr, W>(bytes_to_state(&new_block[32..]));
    let (t, retries) =
        prove_step_with_retry(&mut cur, ext, vec![trivial_acc.clone(); MU - 1], "updated leaf")?;
    path.push(UpdatePathTiming {
        level: 0,
        prove_time: init_time + t,
        retries,
    });

    for k in 1..=depth {
        let sibling = &rep[k - 1];
        let mut ext_v: Vec<Fr> =
            std::iter::repeat(sibling.z_i.clone()).take(MU - 1).flatten().collect();
        ext_v.resize(32 * (W - 1), Fr::from(0u64));
        let ext = ExtDigests::<Fr, W>(ext_v);
        let other = vec![(sibling.U_i.clone(), sibling.W_i.clone()); MU - 1];
        let (t, retries) =
            prove_step_with_retry(&mut cur, ext, other, &format!("update path level {k}"))?;
        path.push(UpdatePathTiming {
            level: k,
            prove_time: t,
            retries,
        });
    }
    let update_peak_mem = probe.peak();

    // --- Verify the updated root + native cross-check ---
    let verify_start = Instant::now();
    HnB::<W, MU>::verify(params.1.clone(), cur.ivc_proof())?;
    let mut verify_time = verify_start.elapsed();

    // Native updated root: leaf 0 changed, all other subtrees unchanged.
    let mut expected = sha256_native(&new_block);
    for k in 1..=depth {
        let mut buf = expected.to_vec();
        for _ in 1..MU {
            buf.extend_from_slice(&d_old[k - 1]);
        }
        buf.resize(32 * W, 0u8);
        expected = sha256_native(&buf);
    }
    let new_root = state_to_bytes(&cur.z_i);
    assert_eq!(
        new_root, expected,
        "updated in-circuit root diverges from native updated Merkle root"
    );

    // --- Optional decider on the updated root accumulator ---
    let (decider_time, decider_peak_mem) = if opts.run_decider {
        probe.reset_peak();
        let t = Instant::now();
        let (decider_pp, decider_vp) =
            DecB::<W, MU>::preprocess(&mut rng, (params.clone(), f_circuit.state_len()))?;
        eprintln!("[hypernova-pcd/update] decider keygen: {:?}", t.elapsed());
        let start = Instant::now();
        let proof = DecB::<W, MU>::prove(rng, decider_pp, cur.clone())?;
        let decider_time = start.elapsed();
        let decider_peak_mem = probe.peak();
        let start = Instant::now();
        let verified = DecB::<W, MU>::verify(
            decider_vp,
            cur.i,
            cur.z_0.clone(),
            cur.z_i.clone(),
            &cur.U_i.get_commitments(),
            &cur.u_i.get_commitments(),
            &proof,
        )?;
        assert!(verified, "decider proof did not verify");
        verify_time += start.elapsed();
        (Some(decider_time), decider_peak_mem)
    } else {
        (None, None)
    };

    Ok(UpdateReport {
        arity: MU,
        bucket_bytes: 32 * W,
        depth,
        n_leaves: opts.n_leaves,
        setup_time,
        initial_tree_time,
        setup_peak_mem,
        path,
        update_peak_mem,
        decider_time,
        decider_peak_mem,
        verify_time,
        new_root,
    })
}

// --------------------------------------------------------------------------
// Parallel batch update (k leaves at once, level-parallel path re-proving)
// --------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BatchLevelTiming {
    pub level: usize,
    /// Number of path-union nodes re-proved at this level.
    pub nodes: usize,
    /// Wall-clock for the level (nodes proved in parallel).
    pub wall: Duration,
    /// Sum of the individual node proving times (total CPU-side work).
    pub work: Duration,
    pub retries: usize,
}

#[derive(Debug, Clone)]
pub struct BatchUpdateReport {
    pub arity: usize,
    /// Bytes hashed per node (32 * W).
    pub bucket_bytes: usize,
    pub depth: usize,
    pub n_leaves: usize,
    pub k: usize,
    pub setup_time: Duration,
    pub initial_tree_time: Duration,
    pub setup_peak_mem: Option<usize>,
    pub levels: Vec<BatchLevelTiming>,
    /// Measured wall-clock of the whole batch update.
    pub total_wall: Duration,
    pub update_peak_mem: Option<usize>,
    pub verify_time: Duration,
    pub new_root: [u8; 32],
}

impl BatchUpdateReport {
    pub fn union_nodes(&self) -> usize {
        self.levels.iter().map(|l| l.nodes).sum()
    }
    pub fn naive_nodes(&self) -> usize {
        self.k * (self.depth + 1)
    }
    pub fn total_work(&self) -> Duration {
        self.levels.iter().map(|l| l.work).sum()
    }
}

pub struct BatchUpdateOptions {
    pub n_leaves: usize,
    /// Number of distinct leaves updated at once.
    pub k: usize,
    /// Rayon threads dedicated to each concurrent node task; concurrent
    /// tasks per wave = cores / task_threads (so the product always covers
    /// the whole machine). Default 8 → 32 task × 8 thread su 256 core.
    pub task_threads: usize,
}

fn batch_new_block(arity: usize, leaf: usize) -> Vec<u8> {
    (0..32 * arity)
        .map(|j| (((leaf as u64).wrapping_mul(131) + (j as u64) * 7 + 13) % 251) as u8 + 1)
        .collect()
}

/// A single prove_step already spreads its internal work (MSMs, sum-check)
/// over rayon's GLOBAL pool, so n concurrent steps would mostly time-slice.
/// Give each concurrent task its own rayon pool with a fair share of the
/// cores: work issued inside `pool.install(..)` stays on that pool.
fn per_task_pool(n_tasks: usize) -> Result<rayon::ThreadPool, Error> {
    let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(16);
    let threads = (cores / n_tasks.max(1)).clamp(4, cores);
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| Error::Other(e.to_string()))
}

/// Update k distinct leaves at once: re-prove the union of the leaf-to-root
/// paths, level by level (barrier), with the nodes of each level proved in
/// parallel. Shared ancestors are re-proved once, folding all their updated
/// children together (that is just the regular MU-ary merge).
pub fn run_batch_update2<const W: usize, const MU: usize>(
    opts: &BatchUpdateOptions,
    probe: MemProbe,
) -> Result<BatchUpdateReport, Error> {
    use std::collections::{BTreeMap, BTreeSet};

    assert!(W >= MU);
    let depth = exact_log(MU, opts.n_leaves);
    assert!(opts.k >= 1 && opts.k <= opts.n_leaves);
    let f_circuit = Fc::<W>::new(())?;

    // --- Setup + initial tree via the clone trick ---
    probe.reset_peak();
    let tree = build_identical_tree::<W, MU>(depth)?;
    let setup_peak_mem = probe.peak();
    eprintln!(
        "[hypernova-pcd/multi-update] arity {MU} bucket {}B: setup {:?}, initial tree {:?}",
        32 * W,
        tree.setup_time, tree.build_time
    );

    // --- Pick k distinct pseudo-random leaves (deterministic) ---
    let mut chosen: BTreeSet<usize> = BTreeSet::new();
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    while chosen.len() < opts.k {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        chosen.insert((x >> 16) as usize % opts.n_leaves);
    }

    // --- The measured batch update ---
    probe.reset_peak();
    let batch_start = Instant::now();
    let mut levels: Vec<BatchLevelTiming> = Vec::with_capacity(depth + 1);

    // Native updated digests per (level, position); unchanged = tree.d_old.
    let mut native: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
    for &leaf in &chosen {
        native.insert(leaf, sha256_native(&batch_new_block(W, leaf)));
    }

    // Level 0: updated leaves, in parallel.
    let mut updated: BTreeMap<usize, HnB<W, MU>> = {
        let lvl_start = Instant::now();
        let params = &tree.params;
        let trivial = &tree.trivial_acc;
        let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(16);
        let max_conc = (cores / opts.task_threads.max(1)).max(4);
        let leaf_list: Vec<usize> = chosen.iter().copied().collect();
        let mut results: Vec<(usize, HnB<W, MU>, Duration, usize)> = Vec::new();
        for wave in leaf_list.chunks(max_conc) {
        let n_tasks = wave.len();
        let wave_results: Vec<(usize, HnB<W, MU>, Duration, usize)> = std::thread::scope(|s| {
            let handles: Vec<_> = wave
                .iter()
                .map(|&leaf| {
                    s.spawn(move || -> Result<(usize, HnB<W, MU>, Duration, usize), Error> {
                        let pool = per_task_pool(n_tasks)?;
                        let t0 = Instant::now();
                        let (hn, retries) = pool.install(
                            || -> Result<(HnB<W, MU>, usize), Error> {
                                let block = batch_new_block(W, leaf);
                                let mut hn = HnB::<W, MU>::init(
                                    params,
                                    f_circuit,
                                    bytes_to_state(&block[..32]),
                                )?;
                                let ext = ExtDigests::<Fr, W>(bytes_to_state(&block[32..]));
                                let (_, retries) = prove_step_with_retry(
                                    &mut hn,
                                    ext,
                                    vec![trivial.clone(); MU - 1],
                                    &format!("batch leaf {leaf}"),
                                )?;
                                Ok((hn, retries))
                            },
                        )?;
                        Ok((leaf, hn, t0.elapsed(), retries))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("leaf worker panicked"))
                .collect::<Result<Vec<_>, Error>>()
        })?;
        results.extend(wave_results);
        }
        let wall = lvl_start.elapsed();
        let work = results.iter().map(|r| r.2).sum();
        let retries = results.iter().map(|r| r.3).sum();
        levels.push(BatchLevelTiming {
            level: 0,
            nodes: results.len(),
            wall,
            work,
            retries,
        });
        results.into_iter().map(|(p, hn, _, _)| (p, hn)).collect()
    };

    // Merge levels, one barrier per level; nodes within a level in parallel.
    for level in 1..=depth {
        let positions: BTreeSet<usize> = updated.keys().map(|p| p / MU).collect();

        // Assemble each parent's inputs (owning moves out of `updated`).
        let mut tasks: Vec<(usize, HnB<W, MU>, Vec<Fr>, Vec<RunningAccB<W, MU>>)> = Vec::new();
        let mut next_native: BTreeMap<usize, [u8; 32]> = BTreeMap::new();
        for &p in &positions {
            let first_child = p * MU;
            let chain = updated
                .remove(&first_child)
                .unwrap_or_else(|| tree.rep[level - 1].clone());
            let mut ext: Vec<Fr> = Vec::with_capacity(32 * (W - 1));
            let mut others: Vec<RunningAccB<W, MU>> = Vec::with_capacity(MU - 1);
            let mut buf: Vec<u8> = state_to_bytes(&chain.z_i).to_vec();
            for c in first_child + 1..first_child + MU {
                if let Some(u) = updated.remove(&c) {
                    ext.extend(u.z_i.clone());
                    buf.extend_from_slice(&state_to_bytes(&u.z_i));
                    others.push((u.U_i.clone(), u.W_i.clone()));
                } else {
                    ext.extend(tree.rep[level - 1].z_i.clone());
                    buf.extend_from_slice(&tree.d_old[level - 1]);
                    others.push((
                        tree.rep[level - 1].U_i.clone(),
                        tree.rep[level - 1].W_i.clone(),
                    ));
                }
            }
            ext.resize(32 * (W - 1), Fr::from(0u64));
            buf.resize(32 * W, 0u8);
            next_native.insert(p, sha256_native(&buf));
            tasks.push((p, chain, ext, others));
        }

        let lvl_start = Instant::now();
        let cores = std::thread::available_parallelism().map(|c| c.get()).unwrap_or(16);
        let max_conc = (cores / opts.task_threads.max(1)).max(4);
        let mut results: Vec<(usize, HnB<W, MU>, Duration, usize)> = Vec::new();
        let mut tasks = tasks;
        while !tasks.is_empty() {
        let take = tasks.len().min(max_conc);
        let wave: Vec<_> = tasks.drain(..take).collect();
        let n_tasks = wave.len();
        let wave_results: Vec<(usize, HnB<W, MU>, Duration, usize)> = std::thread::scope(|s| {
            let handles: Vec<_> = wave
                .into_iter()
                .map(|(p, mut chain, ext, others)| {
                    s.spawn(move || -> Result<(usize, HnB<W, MU>, Duration, usize), Error> {
                        let pool = per_task_pool(n_tasks)?;
                        let t0 = Instant::now();
                        let retries = pool.install(|| -> Result<usize, Error> {
                            let (_, retries) = prove_step_with_retry(
                                &mut chain,
                                ExtDigests::<Fr, W>(ext),
                                others,
                                &format!("batch merge level {level} pos {p}"),
                            )?;
                            Ok(retries)
                        })?;
                        Ok((p, chain, t0.elapsed(), retries))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("merge worker panicked"))
                .collect::<Result<Vec<_>, Error>>()
        })?;
        results.extend(wave_results);
        }
        let wall = lvl_start.elapsed();
        let work = results.iter().map(|r| r.2).sum();
        let retries = results.iter().map(|r| r.3).sum();
        levels.push(BatchLevelTiming {
            level,
            nodes: results.len(),
            wall,
            work,
            retries,
        });
        // Cross-check each updated node against its native digest.
        for (p, hn, _, _) in &results {
            assert_eq!(
                state_to_bytes(&hn.z_i),
                next_native[p],
                "updated node at level {level} pos {p} diverges from native digest"
            );
        }
        updated = results.into_iter().map(|(p, hn, _, _)| (p, hn)).collect();
        native = next_native;
    }
    let total_wall = batch_start.elapsed();
    let update_peak_mem = probe.peak();

    assert_eq!(updated.len(), 1);
    let root = updated.remove(&0).expect("root at position 0");
    let new_root = state_to_bytes(&root.z_i);
    assert_eq!(new_root, native[&0]);

    let verify_start = Instant::now();
    HnB::<W, MU>::verify(tree.params.1.clone(), root.ivc_proof())?;
    let verify_time = verify_start.elapsed();

    Ok(BatchUpdateReport {
        arity: MU,
        bucket_bytes: 32 * W,
        depth,
        n_leaves: opts.n_leaves,
        k: opts.k,
        setup_time: tree.setup_time,
        initial_tree_time: tree.build_time,
        setup_peak_mem,
        levels,
        total_wall,
        update_peak_mem,
        verify_time,
        new_root,
    })
}

/// Non-bucketed multi-update (bucket width == folding arity).
pub fn run_batch_update<const ARITY: usize>(
    opts: &BatchUpdateOptions,
    probe: MemProbe,
) -> Result<BatchUpdateReport, Error> {
    run_batch_update2::<ARITY, ARITY>(opts, probe)
}

pub fn print_batch_report(r: &BatchUpdateReport) {
    println!();
    println!("================================================================================");
    println!(
        " HyperNova PCD multi-update (k leaves at once) — {}-ary tree, {} leaves, k = {}, bucket {}B",
        r.arity, r.n_leaves, r.k, r.bucket_bytes
    );
    println!(
        " config: HyperNova MU={}/NU=1; level-parallel path-union re-proving",
        r.arity
    );
    println!("================================================================================");
    println!(
        "    setup latency      : {:>12}   (initial tree via clone trick: {}, peak mem {})",
        fmt_duration(r.setup_time),
        fmt_duration(r.initial_tree_time),
        r.setup_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
    );
    for l in &r.levels {
        println!(
            "    level {:>2} ({:>3} nodes) : wall {:>10} | work {:>10} | parallel {:.2}x",
            l.level,
            l.nodes,
            fmt_duration(l.wall),
            fmt_duration(l.work),
            l.work.as_secs_f64() / l.wall.as_secs_f64().max(1e-9)
        );
    }
    println!(
        "    path union         : {} nodes re-proved (naive k paths: {}, amortization {:.2}x)",
        r.union_nodes(),
        r.naive_nodes(),
        r.naive_nodes() as f64 / r.union_nodes() as f64
    );
    println!(
        "    TOTAL multi-update : wall {:>10} | work {:>10} | parallel speedup {:.2}x   (peak mem {})",
        fmt_duration(r.total_wall),
        fmt_duration(r.total_work()),
        r.total_work().as_secs_f64() / r.total_wall.as_secs_f64().max(1e-9),
        r.update_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
    );
    let retries: usize = r.levels.iter().map(|l| l.retries).sum();
    if retries > 0 {
        println!("    prover retries     : {retries}");
    }
    println!("    verification       : {:>12}", fmt_duration(r.verify_time));
    println!(
        "    new root           : {}",
        r.new_root.map(|b| format!("{b:02x}")).concat()
    );
    println!("================================================================================");
}

/// Non-bucketed single-leaf update (bucket width == folding arity).
pub fn run_update<const ARITY: usize>(
    opts: &UpdateOptions,
    probe: MemProbe,
) -> Result<UpdateReport, Error> {
    run_update2::<ARITY, ARITY>(opts, probe)
}

pub fn print_update_report(r: &UpdateReport) {
    println!();
    println!("================================================================================");
    println!(
        " HyperNova PCD single-leaf update — {}-ary tree, {} leaves (depth {}, bucket {}B)",
        r.arity, r.n_leaves, r.depth, r.bucket_bytes
    );
    println!(
        " config: HyperNova MU={}/NU=1 on BN254/Grumpkin; Reckle-style path re-proving",
        r.arity
    );
    println!("================================================================================");
    println!(
        "    setup latency      : {:>12}   (initial tree via clone trick: {}, peak mem {})",
        fmt_duration(r.setup_time),
        fmt_duration(r.initial_tree_time),
        r.setup_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
    );
    for p in &r.path {
        let label = if p.level == 0 {
            "leaf re-prove".to_string()
        } else {
            format!("path merge level {}", p.level)
        };
        println!("    {label:<22} : {:>12}", fmt_duration(p.prove_time));
    }
    println!(
        "    TOTAL update       : {:>12}   ({} path nodes, peak mem {})",
        fmt_duration(r.total_update_time()),
        r.path.len(),
        r.update_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
    );
    let total_retries: usize = r.path.iter().map(|p| p.retries).sum();
    if total_retries > 0 {
        println!("    prover retries     : {total_retries}");
    }
    match r.decider_time {
        Some(t) => println!("    final SNARK        : {:>12}   (Groth16 decider on updated root)", fmt_duration(t)),
        None => println!("    final SNARK        :      skipped"),
    }
    println!("    verification       : {:>12}", fmt_duration(r.verify_time));
    println!(
        "    new root           : {}",
        r.new_root.map(|b| format!("{b:02x}")).concat()
    );
    println!("================================================================================");
}

/// Compare single-leaf update latency across arities.
pub fn print_update_comparison(reports: &[UpdateReport]) {
    if reports.len() < 2 {
        return;
    }
    println!();
    println!("--- arity head-to-head (single-leaf update latency, best first) ---");
    let mut ranked: Vec<&UpdateReport> = reports.iter().collect();
    ranked.sort_by_key(|r| r.total_update_time());
    let best = ranked[0].total_update_time().as_secs_f64();
    for r in ranked {
        println!(
            "    arity {:>2}: {:>10}  ({:.2}x)  [{} path nodes over depth {}]",
            r.arity,
            fmt_duration(r.total_update_time()),
            r.total_update_time().as_secs_f64() / best,
            r.path.len(),
            r.depth
        );
    }
}

fn stats(times: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let total: Duration = times.iter().sum();
    let avg = if times.is_empty() {
        Duration::ZERO
    } else {
        total / times.len() as u32
    };
    let min = times.iter().min().copied().unwrap_or_default();
    let max = times.iter().max().copied().unwrap_or_default();
    (avg, min, max, total)
}

pub fn print_report(r: &PcdReport) {
    let n_leaves = r.arity.pow(r.depth as u32);
    let n_nodes = r.nodes.len();
    println!();
    println!("================================================================================");
    println!(
        " HyperNova PCD — {}-ary SHA-256 tree, depth {} ({} leaves, {} nodes, {} data, bucket {}B)",
        r.arity,
        r.depth,
        n_leaves,
        n_nodes,
        fmt_bytes(r.data_bytes),
        r.bucket_bytes
    );
    println!(
        " config: HyperNova MU={}/NU=1 on BN254/Grumpkin, KZG + Pedersen, Groth16 decider",
        r.arity
    );
    println!("================================================================================");
    println!(
        "    setup latency    : {:>12}   (peak mem {})",
        fmt_duration(r.setup_time),
        r.setup_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
    );
    let max_level = r.nodes.iter().map(|n| n.level).max().unwrap_or(0);
    for lvl in 0..=max_level {
        let times: Vec<Duration> = r
            .nodes
            .iter()
            .filter(|n| n.level == lvl)
            .map(|n| n.prove_time)
            .collect();
        let (avg, min, max, total) = stats(&times);
        let label = if lvl == 0 {
            format!("level 0 ({} leaf nodes)", times.len())
        } else {
            format!("level {} ({} merge nodes)", lvl, times.len())
        };
        println!(
            "    {label:<26}: avg {:>10} | min {} | max {} | total {}",
            fmt_duration(avg),
            fmt_duration(min),
            fmt_duration(max),
            fmt_duration(total)
        );
    }
    let all_prove: Vec<Duration> = r.nodes.iter().map(|n| n.prove_time).collect();
    let (avg, _, _, total) = stats(&all_prove);
    println!(
        "    all nodes          : avg {:>10} per node | total tree proving {}   (peak mem {})",
        fmt_duration(avg),
        fmt_duration(total),
        r.tree_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
    );
    println!(
        "    throughput         : {:>12}/s of data proved",
        fmt_bytes(r.throughput_bps() as usize)
    );
    let sib: Vec<Duration> = r.nodes.iter().filter_map(|n| n.sibling_check).collect();
    if !sib.is_empty() {
        let (avg, _, _, total) = stats(&sib);
        println!(
            "    sibling IVC checks : avg {:>10} per merge | total {}   (native, outside circuit)",
            fmt_duration(avg),
            fmt_duration(total)
        );
    }
    let total_retries: usize = r.nodes.iter().map(|n| n.retries).sum();
    if total_retries > 0 {
        println!("    prover retries     : {total_retries} (defensive guard, see README)");
    }
    match r.decider_time {
        Some(t) => println!(
            "    final SNARK        : {:>12}   (Groth16 decider on root accumulator, peak mem {})",
            fmt_duration(t),
            r.decider_peak_mem.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
        ),
        None => println!("    final SNARK        :      skipped"),
    }
    println!("    verification       : {:>12}", fmt_duration(r.verify_time));
    println!(
        "    root digest        : {}",
        r.root_digest.map(|b| format!("{b:02x}")).concat()
    );
    println!("================================================================================");
}

/// Compare throughput across arity runs.
pub fn print_arity_comparison(reports: &[PcdReport]) {
    if reports.len() < 2 {
        return;
    }
    println!();
    println!("--- arity head-to-head (data throughput, best first) ---");
    let mut ranked: Vec<&PcdReport> = reports.iter().collect();
    ranked.sort_by(|a, b| b.throughput_bps().total_cmp(&a.throughput_bps()));
    let best = ranked[0].throughput_bps();
    for r in ranked {
        println!(
            "    arity {:>2}: {:>10}/s  ({:.2}x)  [{} over {} nodes, avg {} per node]",
            r.arity,
            fmt_bytes(r.throughput_bps() as usize),
            r.throughput_bps() / best,
            fmt_bytes(r.data_bytes),
            r.nodes.len(),
            fmt_duration(
                r.total_prove_time() / r.nodes.len().max(1) as u32
            )
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_1_binary_tree_no_decider() -> Result<(), Error> {
        let report = run_pcd::<2>(
            &PcdOptions {
                depth: 1,
                run_decider: false,
                verify_siblings: true,
            },
            MemProbe::NONE,
        )?;
        assert_eq!(report.nodes.len(), 3);
        assert_eq!(
            report.root_digest,
            merkle_root_native(2, &make_blocks(2, 2))
        );
        Ok(())
    }

    #[test]
    fn depth_1_quaternary_tree_no_decider() -> Result<(), Error> {
        let report = run_pcd::<4>(
            &PcdOptions {
                depth: 1,
                run_decider: false,
                verify_siblings: true,
            },
            MemProbe::NONE,
        )?;
        assert_eq!(report.nodes.len(), 5);
        assert_eq!(
            report.root_digest,
            merkle_root_native(4, &make_blocks(4, 4))
        );
        Ok(())
    }
}
