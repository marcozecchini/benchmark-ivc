//! Parallel batch update benchmark: k leaves updated at once in an n-ary
//! HyperNova PCD tree; the union of the leaf-to-root paths is re-proved
//! level by level with the nodes of each level in parallel.
//!
//! ```sh
//! RUSTFLAGS="-C target-cpu=native" cargo bench -p hypernova-pcd --bench batch_update_benchmark -- --arity 4 --leaves 4096 --k 16
//! ```

use bench_common::{MemProbe, PeakAllocator};
use hypernova_pcd::{print_batch_report, run_batch_update, run_batch_update2, BatchUpdateOptions, BatchUpdateReport};

#[global_allocator]
static ALLOC: PeakAllocator = PeakAllocator::new();

fn main() {
    let mut arities = vec![4usize];
    let mut bucket_words: Option<usize> = None;
    let mut n_leaves = 4096usize; // 2^12
    let mut k = 16usize;
    let mut task_threads = 8usize; // thread rayon per task; task per ondata = cores / T

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bucket-words" => {
                let v = args.next().expect("--bucket-words requires a value");
                bucket_words = Some(v.trim().parse().expect("invalid bucket words"));
            }
            "--arity" => {
                let v = args.next().expect("--arity requires a value, e.g. 2,4,8");
                arities = v
                    .split(',')
                    .map(|s| s.trim().parse().expect("invalid arity"))
                    .collect();
            }
            "--leaves" => {
                n_leaves = args
                    .next()
                    .expect("--leaves requires a value")
                    .trim()
                    .parse()
                    .expect("invalid leaf count");
            }
            "--k" => {
                k = args
                    .next()
                    .expect("--k requires a value")
                    .trim()
                    .parse()
                    .expect("invalid k");
            }
            "--task-threads" => {
                task_threads = args
                    .next()
                    .expect("--task-threads requires a value")
                    .trim()
                    .parse()
                    .expect("invalid task threads");
            }
            "--help" | "-h" => {
                eprintln!("usage: batch_update_benchmark [--arity A1,A2,...] [--leaves N] [--k K] [--task-threads T]");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let opts = BatchUpdateOptions { n_leaves, k, task_threads };
    let mut reports: Vec<BatchUpdateReport> = Vec::new();
    for arity in arities {
        eprintln!("\n[arity={arity}] multi-update of k={k} leaves in a {n_leaves}-leaf tree...");
        // Default: arity 4, non-bucketed (updates are the metrics that
        // matter; buckets only pay off for bulk construction).
        let w = bucket_words.unwrap_or(arity);
        let report = match (arity, w) {
            (2, 2) => run_batch_update::<2>(&opts, MemProbe(Some(&ALLOC))),
            (4, 4) => run_batch_update::<4>(&opts, MemProbe(Some(&ALLOC))),
            (8, 8) => run_batch_update::<8>(&opts, MemProbe(Some(&ALLOC))),
            (16, 16) => run_batch_update::<16>(&opts, MemProbe(Some(&ALLOC))),
            (4, 8) => run_batch_update2::<8, 4>(&opts, MemProbe(Some(&ALLOC))),
            (4, 16) => run_batch_update2::<16, 4>(&opts, MemProbe(Some(&ALLOC))),
            (4, 32) => run_batch_update2::<32, 4>(&opts, MemProbe(Some(&ALLOC))),
            (a, w) => panic!("unsupported arity/bucket combo {a}/{w}"),
        }
        .expect("batch update benchmark failed");
        print_batch_report(&report);
        reports.push(report);
    }

    if reports.len() > 1 {
        println!();
        println!("--- arity head-to-head (multi-update wall-clock, best first) ---");
        reports.sort_by_key(|r| r.total_wall);
        let best = reports[0].total_wall.as_secs_f64();
        for r in &reports {
            println!(
                "    arity {:>2}: wall {:>10.2}s  ({:.2}x)  [{} union nodes, work {:.1}s, speedup {:.2}x]",
                r.arity,
                r.total_wall.as_secs_f64(),
                r.total_wall.as_secs_f64() / best,
                r.union_nodes(),
                r.total_work().as_secs_f64(),
                r.total_work().as_secs_f64() / r.total_wall.as_secs_f64().max(1e-9)
            );
        }
    }
}
