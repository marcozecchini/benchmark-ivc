//! HyperNova PCD benchmark entry point.
//!
//! ```sh
//! RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd -- --arity 2,4,8
//! RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd -- --arity 2 --depth 3
//! ```
//!
//! With no `--depth`, each arity gets the depth that yields ~2 KiB of data
//! (arity 2 → depth 5, arity 4 → depth 2, arity 8 → depth 1), so throughput
//! numbers are directly comparable.

use bench_common::{MemProbe, PeakAllocator};
use hypernova_pcd::{print_arity_comparison, print_report, run_pcd, run_pcd2, PcdOptions, PcdReport};

#[global_allocator]
static ALLOC: PeakAllocator = PeakAllocator::new();

fn default_depth(arity: usize) -> usize {
    // ~2 KiB of data per tree: 32 * arity * arity^depth ≈ 2048.
    match arity {
        2 => 5,  // 32 leaves, 63 nodes
        4 => 2,  // 16 leaves, 21 nodes
        8 => 1,  // 8 leaves, 9 nodes
        _ => 1,
    }
}

fn main() {
    let mut arities = vec![4usize];
    let mut bucket_words: Option<usize> = None;
    let mut depth: Option<usize> = None;
    let mut run_decider = false;
    let mut verify_siblings = true;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--arity" => {
                let v = args.next().expect("--arity requires a value, e.g. 2,4,8");
                arities = v
                    .split(',')
                    .map(|s| s.trim().parse().expect("invalid arity"))
                    .collect();
            }
            "--bucket-words" => {
                let v = args.next().expect("--bucket-words requires a value (16/32/64)");
                bucket_words = Some(v.trim().parse().expect("invalid bucket words"));
            }
            "--depth" => {
                let v = args.next().expect("--depth requires a value");
                depth = Some(v.trim().parse().expect("invalid depth"));
            }
            "--decider" => run_decider = true,
            "--skip-decider" => run_decider = false,
            "--no-sibling-check" => verify_siblings = false,
            "--help" | "-h" => {
                eprintln!(
                    "usage: pcd_benchmark [--arity A1,A2,...] [--depth D] [--decider] [--no-sibling-check]"
                );
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let mut reports: Vec<PcdReport> = Vec::new();
    for arity in arities {
        let opts = PcdOptions {
            depth: depth.unwrap_or_else(|| default_depth(arity)),
            run_decider,
            verify_siblings,
        };
        eprintln!(
            "\n[arity={arity}] building HyperNova PCD tree (depth {}, {} leaves)...",
            opts.depth,
            arity.pow(opts.depth as u32)
        );
        let probe = MemProbe(Some(&ALLOC));
        // Default: arity 4, non-bucketed (updates are the metrics that
        // matter; buckets only pay off for bulk construction).
        let w = bucket_words.unwrap_or(arity);
        let report = match (arity, w) {
            (2, 2) => run_pcd::<2>(&opts, probe),
            (4, 4) => run_pcd::<4>(&opts, probe),
            (8, 8) => run_pcd::<8>(&opts, probe),
            (16, 16) => run_pcd::<16>(&opts, probe),
            // bucketed variants: circuit width W words, folding arity 4
            (4, 8) => run_pcd2::<8, 4>(&opts, probe),
            (4, 16) => run_pcd2::<16, 4>(&opts, probe),
            (4, 32) => run_pcd2::<32, 4>(&opts, probe),
            (4, 64) => run_pcd2::<64, 4>(&opts, probe),
            (a, w) => panic!("unsupported arity/bucket combo {a}/{w}"),
        }
        .expect("PCD run failed");
        print_report(&report);
        reports.push(report);
    }
    print_arity_comparison(&reports);
}
