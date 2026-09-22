//! Reckle-style single-leaf update benchmark (eprint 2024/493 cost model):
//! updating one leaf in an n-ary HyperNova PCD tree re-proves only the
//! leaf-to-root path, folding the stored (unchanged) sibling accumulators.
//!
//! ```sh
//! RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd --bench update_benchmark -- --arity 2,4,8,16 --leaves 4096
//! ```

use bench_common::{MemProbe, PeakAllocator};
use hypernova_pcd::{
    print_update_comparison, print_update_report, run_update, run_update2, UpdateOptions,
    UpdateReport,
};

#[global_allocator]
static ALLOC: PeakAllocator = PeakAllocator::new();

fn main() {
    let mut arities = vec![4usize];
    let mut bucket_words: Option<usize> = None;
    let mut n_leaves = 4096usize; // 2^12
    let mut run_decider = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bucket-words" => {
                let v = args.next().expect("--bucket-words requires a value");
                bucket_words = Some(v.trim().parse().expect("invalid bucket words"));
            }
            "--arity" => {
                let v = args.next().expect("--arity requires a value, e.g. 2,4,8,16");
                arities = v
                    .split(',')
                    .map(|s| s.trim().parse().expect("invalid arity"))
                    .collect();
            }
            "--leaves" => {
                let v = args.next().expect("--leaves requires a value");
                n_leaves = v.trim().parse().expect("invalid leaf count");
            }
            "--decider" => run_decider = true,
            "--help" | "-h" => {
                eprintln!("usage: update_benchmark [--arity A1,A2,...] [--leaves N] [--decider]");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let opts = UpdateOptions {
        n_leaves,
        run_decider,
    };
    let mut reports: Vec<UpdateReport> = Vec::new();
    for arity in arities {
        eprintln!("\n[arity={arity}] single-leaf update in a {n_leaves}-leaf tree...");
        // Default: arity 4, non-bucketed (updates are the metrics that
        // matter; buckets only pay off for bulk construction).
        let w = bucket_words.unwrap_or(arity);
        let report = match (arity, w) {
            (2, 2) => run_update::<2>(&opts, MemProbe(Some(&ALLOC))),
            (4, 4) => run_update::<4>(&opts, MemProbe(Some(&ALLOC))),
            (8, 8) => run_update::<8>(&opts, MemProbe(Some(&ALLOC))),
            (16, 16) => run_update::<16>(&opts, MemProbe(Some(&ALLOC))),
            (4, 8) => run_update2::<8, 4>(&opts, MemProbe(Some(&ALLOC))),
            (4, 16) => run_update2::<16, 4>(&opts, MemProbe(Some(&ALLOC))),
            (4, 32) => run_update2::<32, 4>(&opts, MemProbe(Some(&ALLOC))),
            (a, w) => panic!("unsupported arity/bucket combo {a}/{w}"),
        }
        .expect("update benchmark failed");
        print_update_report(&report);
        reports.push(report);
    }
    print_update_comparison(&reports);
}
