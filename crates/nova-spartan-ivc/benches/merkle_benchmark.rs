//! Merkle-append IVC benchmark on Nova (microsoft/nova-snark) + Spartan.
//!
//! Each folding step appends one leaf to an incremental (frontier-based)
//! SHA-256 Merkle tree of fixed depth and updates the root carried in the
//! IVC state; the final proof is compressed with transparent Spartan+IPA.
//!
//! Run with (RUSTFLAGS set for native CPU features, see README):
//!
//! ```sh
//! cargo bench -p nova-spartan-ivc --bench merkle_benchmark -- --steps 10 --depth 32
//! cargo bench -p nova-spartan-ivc --bench merkle_benchmark -- --steps 10,50 --depth 8,16,32 --skip-spartan
//! ```
//!
//! Beware: the step circuit costs `depth` two-block SHA-256 hashes, so at the
//! default depth 32 it is ~60x the SHA-256 chain circuit (multi-million
//! constraints): setup and the final Spartan proof take minutes and several
//! GiB. Use a smaller `--depth` (or `--skip-spartan`) for quick runs.

use bench_common::{fmt_bytes, fmt_duration, IvcReport, MemProbe, PeakAllocator};
use nova_spartan_ivc::merkle::{run_merkle_ivc, MerkleIvcOutput};
use nova_spartan_ivc::NovaCurve;

#[global_allocator]
static ALLOC: PeakAllocator = PeakAllocator::new();

#[derive(Debug, Clone)]
struct Opts {
    /// Numbers of leaves to append (one leaf per IVC step).
    steps: Vec<usize>,
    /// Tree depths to benchmark (capacity 2^depth leaves).
    depths: Vec<usize>,
    /// Whether to run the final Spartan+IPA compression.
    run_spartan: bool,
    curve: NovaCurve,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            steps: vec![10],
            depths: vec![32],
            run_spartan: true,
            curve: NovaCurve::Bn254,
        }
    }
}

fn parse_list(v: &str, what: &str) -> Vec<usize> {
    v.split(',')
        .map(|s| s.trim().parse().unwrap_or_else(|_| panic!("invalid {what}: {s:?}")))
        .collect()
}

fn parse_args(args: impl Iterator<Item = String>) -> Opts {
    let mut opts = Opts::default();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--steps" => {
                let v = args.next().expect("--steps requires a value, e.g. 10,50");
                opts.steps = parse_list(&v, "step count");
            }
            "--depth" => {
                let v = args.next().expect("--depth requires a value, e.g. 8,16,32");
                opts.depths = parse_list(&v, "depth");
                assert!(
                    opts.depths.iter().all(|d| (1..=64).contains(d)),
                    "depth must be in 1..=64"
                );
            }
            "--skip-spartan" | "--skip-decider" => opts.run_spartan = false,
            "--nova-curve" => {
                let v = args.next().expect("--nova-curve requires pasta|bn254");
                opts.curve = match v.as_str() {
                    "pasta" => NovaCurve::Pasta,
                    "bn254" => NovaCurve::Bn254,
                    other => panic!("unknown curve {other:?}, expected pasta|bn254"),
                };
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: merkle_benchmark [--steps N1,N2,...] [--depth D1,D2,...] \
                     [--skip-spartan] [--nova-curve pasta|bn254]\n\
                     note: step cost is linear in depth (depth x 2-block SHA-256); \
                     depth 32 means a multi-million-constraint step circuit"
                );
                std::process::exit(0);
            }
            // Ignore libtest-style flags that `cargo bench` may pass through.
            other if other.starts_with("--") => {}
            _ => {}
        }
    }
    opts
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn opt_mem(m: Option<usize>) -> String {
    m.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
}

fn print_report(depth: usize, out: &MerkleIvcOutput) {
    let r: &IvcReport = &out.report;
    println!();
    println!("================================================================================");
    println!(
        " IVC benchmark — Merkle append (SHA-256, frontier), depth = {depth}, N = {} leaves",
        r.n_steps()
    );
    println!("================================================================================");
    println!("    config           : {}", r.config);
    println!(
        "    setup latency    : {:>12}   (peak mem {})",
        fmt_duration(r.setup_time),
        opt_mem(r.setup_peak_mem)
    );
    println!(
        "    step proving     : avg {:>10} | min {} | max {} | total {}   (peak mem {})",
        fmt_duration(r.avg_step_time()),
        fmt_duration(r.min_step_time()),
        fmt_duration(r.max_step_time()),
        fmt_duration(r.total_step_time()),
        opt_mem(r.steps_peak_mem)
    );
    match r.finalize_time {
        Some(t) => println!(
            "    final SNARK      : {:>12}   (peak mem {})",
            fmt_duration(t),
            opt_mem(r.finalize_peak_mem)
        ),
        None => println!("    final SNARK      :      skipped   (--skip-spartan)"),
    }
    if let Some(t) = r.verify_time {
        println!("    verification     : {:>12}", fmt_duration(t));
    }
    println!("    final root       : {}", hex(&out.root));
    println!("================================================================================");
}

fn main() {
    let opts = parse_args(std::env::args().skip(1));
    eprintln!(
        "Merkle-append IVC benchmark (Nova + Spartan): depths = {:?}, N = {:?}, spartan = {}, curve = {:?}",
        opts.depths, opts.steps, opts.run_spartan, opts.curve
    );

    for &depth in &opts.depths {
        for &n in &opts.steps {
            eprintln!(
                "\n[depth={depth}, N={n}] running Microsoft Nova + Spartan Merkle append ({:?} cycle)...",
                opts.curve
            );
            let out = run_merkle_ivc(depth, n, opts.run_spartan, opts.curve, MemProbe(Some(&ALLOC)))
                .expect("merkle IVC failed");
            for (i, t) in out.report.step_times.iter().enumerate() {
                eprintln!("  append step {:>3}: {:?}", i + 1, t);
            }
            print_report(depth, &out);
        }
    }
}
