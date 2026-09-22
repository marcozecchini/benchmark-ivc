//! Comparative IVC benchmark entry point.
//!
//! Run with (RUSTFLAGS set for native CPU features, see README):
//!
//! ```sh
//! cargo bench -p ivc-bench -- --steps 10,50,100
//! cargo bench -p ivc-bench -- --steps 10 --skip-decider
//! ```
//!
//! Timing uses `std::time::Instant`; RAM is tracked by a counting global
//! allocator (peak live heap bytes per phase).

use bench_common::{MemProbe, PeakAllocator};

#[global_allocator]
static ALLOC: PeakAllocator = PeakAllocator::new();

fn main() {
    let opts = ivc_bench::parse_args(std::env::args().skip(1));
    ivc_bench::run(&opts, MemProbe(Some(&ALLOC)));
}
