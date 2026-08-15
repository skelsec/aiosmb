use std::hint::black_box;

use aiosmb_compression::{CodecError, compress, decompress, lz4, lz77_huffman, lznt1};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

type Compress = fn(&[u8]) -> Result<Vec<u8>, CodecError>;
type Decompress = fn(&[u8], usize, usize) -> Result<Vec<u8>, CodecError>;

fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    let repetitive = b"abcabcabcabcabcabc".repeat(64 * 1024);
    let structured = (0..1024 * 1024)
        .map(|index| ((index / 97) ^ (index / 4096)) as u8)
        .collect();
    let mut state = 0x1234_5678u32;
    let random = (0..1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    vec![
        ("repetitive", repetitive),
        ("structured", structured),
        ("random", random),
    ]
}

fn codecs() -> [(&'static str, Compress, Decompress); 4] {
    [
        ("lz77", compress, decompress),
        ("lznt1", lznt1::compress, lznt1::decompress),
        (
            "lz77_huffman",
            lz77_huffman::compress,
            lz77_huffman::decompress,
        ),
        ("lz4", lz4::compress, lz4::decompress),
    ]
}

fn compression_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("compress");
    for (codec_name, codec, _) in codecs() {
        for (input_name, input) in inputs() {
            let encoded = codec(&input).expect("benchmark input is valid");
            eprintln!(
                "{codec_name}/{input_name} ratio: {:.4}",
                encoded.len() as f64 / input.len() as f64
            );
            group.throughput(Throughput::Bytes(input.len() as u64));
            group.bench_with_input(
                BenchmarkId::new(codec_name, input_name),
                &input,
                |bencher, data| {
                    bencher.iter(|| codec(black_box(data)).expect("benchmark input is valid"));
                },
            );
        }
    }
    group.finish();
}

fn decompression_benchmarks(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("decompress");
    for (codec_name, compressor, decoder) in codecs() {
        for (input_name, input) in inputs() {
            let encoded = compressor(&input).expect("benchmark setup should compress");
            group.throughput(Throughput::Bytes(input.len() as u64));
            group.bench_function(BenchmarkId::new(codec_name, input_name), |bencher| {
                bencher.iter(|| {
                    decoder(
                        black_box(&encoded),
                        black_box(input.len()),
                        black_box(input.len()),
                    )
                    .expect("benchmark stream is valid")
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, compression_benchmarks, decompression_benchmarks);
criterion_main!(benches);
