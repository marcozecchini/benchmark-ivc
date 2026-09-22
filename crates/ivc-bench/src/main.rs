//! Binary twin of `benches/ivc_benchmark.rs`, for `cargo run --release -p ivc-bench`.

use bench_common::{MemProbe, PeakAllocator};

#[global_allocator]
static ALLOC: PeakAllocator = PeakAllocator::new();

fn main() {
    let opts = ivc_bench::parse_args(std::env::args().skip(1));
    ivc_bench::run(&opts, MemProbe(Some(&ALLOC)));
}
