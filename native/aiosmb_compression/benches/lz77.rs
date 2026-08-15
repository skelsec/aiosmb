use std::hint::black_box;

use aiosmb_compression::{compress, decompress};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    let repetitive = b"abcabcabcabcabcabc".repeat(64 * 1024);
    let mut state = 0x1234_5678u32;
    let random = (0..1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    vec![("repetitive", repetitive), ("random", random)]
}

fn compression_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("compress_lz77");
    for (name, input) in inputs() {
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &input,
            |bencher, data| {
                bencher.iter(|| compress(black_box(data)).expect("benchmark input is valid"));
            },
        );
    }
    group.finish();
}

fn decompression_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decompress_lz77");
    for (name, input) in inputs() {
        let compressed = compress(&input).expect("benchmark setup should compress");
        group.throughput(Throughput::Bytes(input.len() as u64));
        group.bench_function(BenchmarkId::from_parameter(name), |bencher| {
            bencher.iter(|| {
                decompress(
                    black_box(&compressed),
                    black_box(input.len()),
                    black_box(input.len()),
                )
                .expect("benchmark stream is valid")
            });
        });
    }
    group.finish();
}

criterion_group!(benches, compression_benchmarks, decompression_benchmarks);
criterion_main!(benches);
