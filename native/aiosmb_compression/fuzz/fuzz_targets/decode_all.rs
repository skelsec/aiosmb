#![no_main]

use aiosmb_compression::{lz4, lz77_huffman, lznt1};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_OUTPUT: usize = 1024 * 1024;

fuzz_target!(|input: &[u8]| {
    if input.len() < 5 {
        return;
    }
    let algorithm = input[0] % 3;
    let expected_size =
        u32::from_le_bytes(input[1..5].try_into().expect("size header is four bytes")) as usize
            % MAX_FUZZ_OUTPUT;
    let compressed = &input[5..];
    match algorithm {
        0 => {
            let _ = lznt1::decompress(compressed, expected_size, MAX_FUZZ_OUTPUT);
        }
        1 => {
            let _ = lz77_huffman::decompress(compressed, expected_size, MAX_FUZZ_OUTPUT);
        }
        _ => {
            let _ = lz4::decompress(compressed, expected_size, MAX_FUZZ_OUTPUT);
        }
    }
});
