//! Shared driver for the comparative IVC benchmark (used by both the
//! `ivc_benchmark` bench target and the `ivc-bench` binary).

use bench_common::{print_comparative_report, IvcReport, MemProbe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Plonky2,
    Sonobe,
    NovaSpartan,
}

#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// IVC chain lengths to benchmark (e.g. 10, 50, 100).
    pub steps: Vec<usize>,
    /// Whether to run the final-SNARK stages (Sonobe's Groth16 Decider and
    /// Nova's Spartan compression).
    pub run_decider: bool,
    /// Restrict the run to a single backend.
    pub only: Option<Backend>,
    /// Curve cycle for the Microsoft-Nova backend.
    pub nova_curve: nova_spartan_ivc::NovaCurve,
    /// The 32-byte input of the first SHA-256 step.
    pub input: [u8; 32],
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            steps: vec![10],
            run_decider: true,
            only: None,
            // Default chosen empirically: fastest prove_step on this codebase
            // (see README, "Scelta della curva per Nova/Spartan").
            nova_curve: nova_spartan_ivc::NovaCurve::Bn254,
            input: *b"TransLog IVC benchmark seed 0001",
        }
    }
}

pub fn parse_args(args: impl Iterator<Item = String>) -> BenchOptions {
    let mut opts = BenchOptions::default();
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--steps" => {
                let v = args.next().expect("--steps requires a value, e.g. 10,50,100");
                opts.steps = v
                    .split(',')
                    .map(|s| s.trim().parse().expect("invalid step count"))
                    .collect();
            }
            "--skip-decider" => opts.run_decider = false,
            "--only" => {
                let v = args.next().expect("--only requires plonky2|sonobe|nova");
                opts.only = Some(match v.as_str() {
                    "plonky2" => Backend::Plonky2,
                    "sonobe" => Backend::Sonobe,
                    "nova" | "nova-spartan" => Backend::NovaSpartan,
                    other => panic!("unknown backend {other:?}, expected plonky2|sonobe|nova"),
                });
            }
            "--nova-curve" => {
                let v = args.next().expect("--nova-curve requires pasta|bn254");
                opts.nova_curve = match v.as_str() {
                    "pasta" => nova_spartan_ivc::NovaCurve::Pasta,
                    "bn254" => nova_spartan_ivc::NovaCurve::Bn254,
                    other => panic!("unknown curve {other:?}, expected pasta|bn254"),
                };
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: ivc_benchmark [--steps N1,N2,...] [--skip-decider] \
                     [--only plonky2|sonobe|nova] [--nova-curve pasta|bn254]"
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

fn should_run(opts: &BenchOptions, backend: Backend) -> bool {
    opts.only.is_none() || opts.only == Some(backend)
}

pub fn run(opts: &BenchOptions, probe: MemProbe) {
    eprintln!(
        "IVC benchmark: SHA-256 single block (32-byte state), N = {:?}, decider = {}",
        opts.steps, opts.run_decider
    );

    for &n in &opts.steps {
        let mut reports: Vec<IvcReport> = Vec::new();

        if should_run(opts, Backend::Plonky2) {
            eprintln!("\n[N={n}] running Plonky2 (Goldilocks + Poseidon, cyclic recursion)...");
            let out = plonky2_ivc::run_ivc(opts.input, n, probe).expect("plonky2 IVC failed");
            for (i, t) in out.report.step_times.iter().enumerate() {
                eprintln!("  plonky2 recursive step {:>3}: {:?}", i + 1, t);
            }
            reports.push(out.report);
        }

        if should_run(opts, Backend::Sonobe) {
            eprintln!("\n[N={n}] running Sonobe (Nova + CycleFold on BN254/Grumpkin)...");
            let out = sonobe_ivc::run_ivc(opts.input, n, opts.run_decider, probe)
                .expect("sonobe IVC failed");
            for (i, t) in out.report.step_times.iter().enumerate() {
                eprintln!("  sonobe folding step  {:>3}: {:?}", i + 1, t);
            }
            reports.push(out.report);
        }

        if should_run(opts, Backend::NovaSpartan) {
            eprintln!(
                "\n[N={n}] running Microsoft Nova + Spartan ({:?} cycle)...",
                opts.nova_curve
            );
            let out =
                nova_spartan_ivc::run_ivc(opts.input, n, opts.run_decider, opts.nova_curve, probe)
                    .expect("nova+spartan IVC failed");
            for (i, t) in out.report.step_times.iter().enumerate() {
                eprintln!("  nova folding step    {:>3}: {:?}", i + 1, t);
            }
            reports.push(out.report);
        }

        print_comparative_report(n, &reports);
    }
}
