#![no_main]

use aiosmb_compression::{lz4, lz77_huffman, lznt1};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 1024 * 1024;

fuzz_target!(|input: &[u8]| {
    if input.is_empty() || input.len() > MAX_FUZZ_INPUT {
        return;
    }
    let (algorithm, plain) = (input[0] % 3, &input[1..]);
    let compressed = match algorithm {
        0 => lznt1::compress(plain),
        1 => lz77_huffman::compress(plain),
        _ => lz4::compress(plain),
    }
    .expect("bounded input should compress");
    let decompressed = match algorithm {
        0 => lznt1::decompress(&compressed, plain.len(), plain.len()),
        1 => lz77_huffman::decompress(&compressed, plain.len(), plain.len()),
        _ => lz4::decompress(&compressed, plain.len(), plain.len()),
    }
    .expect("the encoder must produce a valid stream");
    assert_eq!(decompressed, plain);
});
