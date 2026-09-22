//! Shared benchmarking utilities: peak-memory tracking allocator and the
//! timing-report data model used by both IVC backends.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A counting wrapper around the system allocator that tracks the current and
/// peak number of live heap bytes. Install it as `#[global_allocator]` in the
/// benchmark binary:
///
/// ```ignore
/// #[global_allocator]
/// static ALLOC: bench_common::PeakAllocator = bench_common::PeakAllocator::new();
/// ```
pub struct PeakAllocator {
    current: AtomicUsize,
    peak: AtomicUsize,
}

impl PeakAllocator {
    pub const fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// Live heap bytes right now.
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    /// Peak live heap bytes since the last [`PeakAllocator::reset_peak`].
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    /// Reset the peak marker to the current live size, so the next phase
    /// measures its own high-water mark.
    pub fn reset_peak(&self) {
        self.peak
            .store(self.current.load(Ordering::Relaxed), Ordering::Relaxed);
    }

    fn add(&self, bytes: usize) {
        let cur = self.current.fetch_add(bytes, Ordering::Relaxed) + bytes;
        self.peak.fetch_max(cur, Ordering::Relaxed);
    }

    fn sub(&self, bytes: usize) {
        self.current.fetch_sub(bytes, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for PeakAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            self.add(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        self.sub(layout.size());
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            self.add(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            self.sub(layout.size());
            self.add(new_size);
        }
        new_ptr
    }
}

/// Handle the backends use to record per-phase peak memory without owning the
/// global allocator themselves. The benchmark binary passes a reference to its
/// installed [`PeakAllocator`]; library tests can pass `None`.
#[derive(Clone, Copy)]
pub struct MemProbe(pub Option<&'static PeakAllocator>);

impl MemProbe {
    pub const NONE: MemProbe = MemProbe(None);

    pub fn reset_peak(&self) {
        if let Some(a) = self.0 {
            a.reset_peak();
        }
    }

    pub fn peak(&self) -> Option<usize> {
        self.0.map(|a| a.peak())
    }
}

/// Timing/memory report for one IVC backend run.
#[derive(Debug, Clone)]
pub struct IvcReport {
    /// Human-readable backend label.
    pub backend: String,
    /// Field / curve configuration description.
    pub config: String,
    /// One-time cryptographic setup latency (params + keys + base circuit build).
    pub setup_time: Duration,
    /// Peak heap during setup, if measured.
    pub setup_peak_mem: Option<usize>,
    /// Per-step proving time (recursive proof for Plonky2, folding step for Sonobe).
    pub step_times: Vec<Duration>,
    /// Peak heap during the stepping loop, if measured.
    pub steps_peak_mem: Option<usize>,
    /// Final proof compression: Sonobe's Decider (Groth16+KZG). `None` for
    /// Plonky2, whose last recursive proof is already the final proof.
    pub finalize_time: Option<Duration>,
    /// Peak heap during finalization, if measured.
    pub finalize_peak_mem: Option<usize>,
    /// Time spent verifying the final proof (sanity check that the run is sound).
    pub verify_time: Option<Duration>,
}

impl IvcReport {
    pub fn n_steps(&self) -> usize {
        self.step_times.len()
    }

    pub fn total_step_time(&self) -> Duration {
        self.step_times.iter().sum()
    }

    pub fn avg_step_time(&self) -> Duration {
        if self.step_times.is_empty() {
            Duration::ZERO
        } else {
            self.total_step_time() / self.step_times.len() as u32
        }
    }

    pub fn min_step_time(&self) -> Duration {
        self.step_times.iter().min().copied().unwrap_or_default()
    }

    pub fn max_step_time(&self) -> Duration {
        self.step_times.iter().max().copied().unwrap_or_default()
    }
}

pub fn fmt_bytes(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b >= KB * KB * KB {
        format!("{:.2} GiB", b / (KB * KB * KB))
    } else if b >= KB * KB {
        format!("{:.2} MiB", b / (KB * KB))
    } else if b >= KB {
        format!("{:.2} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

pub fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s >= 60.0 {
        format!("{:.0}m{:04.1}s", (s / 60.0).floor(), s % 60.0)
    } else if s >= 1.0 {
        format!("{s:.3} s")
    } else {
        format!("{:.2} ms", s * 1000.0)
    }
}

fn opt_mem(m: Option<usize>) -> String {
    m.map(fmt_bytes).unwrap_or_else(|| "n/a".into())
}

/// Print the final comparative report for a set of backend runs at the same N.
pub fn print_comparative_report(n_steps: usize, reports: &[IvcReport]) {
    println!();
    println!("================================================================================");
    println!(" IVC benchmark — SHA-256 chain over 32-byte state, N = {n_steps} steps");
    println!("================================================================================");
    for r in reports {
        println!();
        println!("--- {} ---", r.backend);
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
            None => println!("    final SNARK      :          n/a   (last recursive proof is final)"),
        }
        if let Some(t) = r.verify_time {
            println!("    verification     : {:>12}", fmt_duration(t));
        }
    }
    println!();
    println!("--- head-to-head (avg per-step proving, fastest first) ---");
    let mut ranked: Vec<&IvcReport> = reports.iter().collect();
    ranked.sort_by_key(|r| r.avg_step_time());
    if let Some(fastest) = ranked.first() {
        let base = fastest.avg_step_time().as_secs_f64().max(1e-12);
        for r in &ranked {
            let ratio = r.avg_step_time().as_secs_f64() / base;
            println!(
                "    {:>8} /step  ({ratio:.2}x)  {}",
                fmt_duration(r.avg_step_time()),
                r.backend
            );
        }
    }
    println!("================================================================================");
}
