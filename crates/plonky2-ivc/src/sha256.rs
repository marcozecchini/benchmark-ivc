//! Bit-level SHA-256 gadget for Plonky2 (single 512-bit block, 32-byte message).
//!
//! The 32-byte message occupies exactly half a block, so padding is constant:
//! `msg (256 bits) || 0x80... (1 bit + 191 zeros) || len=256 (64 bits)`.
//! Words are kept as 32 LSB-first `BoolTarget`s plus their packed `Target`.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[rustfmt::skip]
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A 32-bit word: LSB-first bits plus the packed field element.
#[derive(Clone)]
struct Word {
    bits: Vec<BoolTarget>,
    word: Target,
}

fn xor2<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
) -> BoolTarget {
    // x ^ y = x + y - 2xy
    let s = b.add(x.target, y.target);
    BoolTarget::new_unsafe(b.arithmetic(-F::TWO, F::ONE, x.target, y.target, s))
}

fn xor3<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
    z: BoolTarget,
) -> BoolTarget {
    let t = xor2(b, x, y);
    xor2(b, t, z)
}

/// ch(e, f, g) = if e { f } else { g }
fn ch<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    e: BoolTarget,
    f: BoolTarget,
    g: BoolTarget,
) -> BoolTarget {
    BoolTarget::new_unsafe(b.select(e, f.target, g.target))
}

/// maj(x, y, z) = if x ^ y { z } else { x }
fn maj<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    x: BoolTarget,
    y: BoolTarget,
    z: BoolTarget,
) -> BoolTarget {
    let xy = xor2(b, x, y);
    BoolTarget::new_unsafe(b.select(xy, z.target, x.target))
}

/// rotr: output bit i = input bit (i + n) mod 32 (LSB-first indexing).
fn rotr(bits: &[BoolTarget], n: usize) -> Vec<BoolTarget> {
    (0..32).map(|i| bits[(i + n) % 32]).collect()
}

/// Big sigma: rotr(a) ^ rotr(b) ^ rotr(c), bitwise.
fn big_sigma<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    w: &Word,
    r1: usize,
    r2: usize,
    r3: usize,
) -> Vec<BoolTarget> {
    let a1 = rotr(&w.bits, r1);
    let a2 = rotr(&w.bits, r2);
    let a3 = rotr(&w.bits, r3);
    (0..32).map(|i| xor3(b, a1[i], a2[i], a3[i])).collect()
}

/// Small sigma: rotr(r1) ^ rotr(r2) ^ shr(s). For bit positions where the
/// shifted-out operand vanishes, only a 2-way xor is needed.
fn small_sigma<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    w: &Word,
    r1: usize,
    r2: usize,
    s: usize,
) -> Vec<BoolTarget> {
    let a1 = rotr(&w.bits, r1);
    let a2 = rotr(&w.bits, r2);
    (0..32)
        .map(|i| {
            if i + s < 32 {
                xor3(b, a1[i], a2[i], w.bits[i + s])
            } else {
                xor2(b, a1[i], a2[i])
            }
        })
        .collect()
}

fn pack<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Target {
    b.le_sum(bits.iter())
}

/// Add raw (unreduced) targets, then reduce mod 2^32. `num_bits` must bound
/// the raw sum (sum of k words needs ceil(log2(k)) + 32 bits).
fn add_mod32<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    terms: &[Target],
    num_bits: usize,
) -> Word {
    let raw = b.add_many(terms.iter().copied());
    let all_bits = b.split_le(raw, num_bits);
    let bits: Vec<BoolTarget> = all_bits[..32].to_vec();
    let word = pack(b, &bits);
    Word { bits, word }
}

fn constant_word<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    value: u32,
) -> Word {
    let bits = (0..32)
        .map(|i| b.constant_bool((value >> i) & 1 == 1))
        .collect();
    let word = b.constant(F::from_canonical_u32(value));
    Word { bits, word }
}

/// SHA-256 of a 32-byte message given as 8 big-endian u32 words.
///
/// Each input target is range-checked to 32 bits by the initial `split_le`.
/// Returns the 8 output words (each already reduced to 32 bits).
pub fn sha256_32bytes<F: RichField + Extendable<D>, const D: usize>(
    b: &mut CircuitBuilder<F, D>,
    input_words: &[Target; 8],
) -> [Target; 8] {
    // Message schedule W[0..16]: 8 message words + constant padding.
    let mut w: Vec<Word> = Vec::with_capacity(64);
    for &t in input_words {
        let bits = b.split_le(t, 32);
        w.push(Word { bits, word: t });
    }
    w.push(constant_word(b, 0x8000_0000)); // 1-bit terminator
    for _ in 9..15 {
        w.push(constant_word(b, 0));
    }
    w.push(constant_word(b, 256)); // message length in bits

    // W[16..64]
    for t in 16..64 {
        let s0 = small_sigma(b, &w[t - 15], 7, 18, 3);
        let s1 = small_sigma(b, &w[t - 2], 17, 19, 10);
        let s0w = pack(b, &s0);
        let s1w = pack(b, &s1);
        // 4 words: raw sum < 2^34
        let next = add_mod32(b, &[s1w, w[t - 7].word, s0w, w[t - 16].word], 34);
        w.push(next);
    }

    // Working variables start at the IV (fresh single-block hash each step).
    let mut vars: Vec<Word> = IV.iter().map(|&v| constant_word(b, v)).collect();

    for t in 0..64 {
        let (a, bb, c, d, e, f, g, h) = (
            vars[0].clone(),
            vars[1].clone(),
            vars[2].clone(),
            vars[3].clone(),
            vars[4].clone(),
            vars[5].clone(),
            vars[6].clone(),
            vars[7].clone(),
        );
        let s1 = big_sigma(b, &e, 6, 11, 25);
        let s1w = pack(b, &s1);
        let chb: Vec<BoolTarget> = (0..32).map(|i| ch(b, e.bits[i], f.bits[i], g.bits[i])).collect();
        let chw = pack(b, &chb);
        let k = b.constant(F::from_canonical_u32(K[t]));
        // temp1 = h + S1 + ch + K + W[t]  (raw, < 5 * 2^32)
        let temp1 = b.add_many([h.word, s1w, chw, k, w[t].word]);

        let s0 = big_sigma(b, &a, 2, 13, 22);
        let s0w = pack(b, &s0);
        let mjb: Vec<BoolTarget> = (0..32)
            .map(|i| maj(b, a.bits[i], bb.bits[i], c.bits[i]))
            .collect();
        let mjw = pack(b, &mjb);

        // e' = d + temp1 (raw < 6 * 2^32 < 2^35)
        let new_e = add_mod32(b, &[d.word, temp1], 35);
        // a' = temp1 + S0 + maj (raw < 7 * 2^32 < 2^35)
        let new_a = add_mod32(b, &[temp1, s0w, mjw], 35);

        vars = vec![new_a, a, bb, c, new_e, e, f, g];
    }

    // H'[j] = IV[j] + var[j] (raw < 2^33)
    core::array::from_fn(|j| {
        let iv = b.constant(F::from_canonical_u32(IV[j]));
        add_mod32(b, &[iv, vars[j].word], 33).word
    })
}

/// Native single-block SHA-256 chain helper: words of sha256(state).
pub fn sha256_chain_native(input: [u8; 32], n_steps: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut state = input;
    for _ in 0..n_steps {
        let out = Sha256::digest(state);
        state.copy_from_slice(&out);
    }
    state
}

/// Pack 32 bytes into 8 big-endian u32 words.
pub fn bytes_to_words(bytes: [u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_be_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}
