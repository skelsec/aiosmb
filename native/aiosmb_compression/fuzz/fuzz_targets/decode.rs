#![no_main]

use aiosmb_compression::decompress;
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_OUTPUT: usize = 1024 * 1024;

fuzz_target!(|input: &[u8]| {
    let (size_bytes, compressed) = if input.len() >= 4 {
        input.split_at(4)
    } else {
        (&[0, 0, 0, 0][..], input)
    };
    let expected_size =
        u32::from_le_bytes(size_bytes.try_into().expect("size header is four bytes")) as usize
            % MAX_FUZZ_OUTPUT;
    let _ = decompress(compressed, expected_size, MAX_FUZZ_OUTPUT);
});
