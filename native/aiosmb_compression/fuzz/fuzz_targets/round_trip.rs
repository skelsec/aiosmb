#![no_main]

use aiosmb_compression::{compress, decompress};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_INPUT: usize = 1024 * 1024;

fuzz_target!(|input: &[u8]| {
    if input.len() <= MAX_FUZZ_INPUT {
        let compressed = compress(input).expect("bounded input should compress");
        let decompressed = decompress(&compressed, input.len(), input.len())
            .expect("the encoder must produce a valid stream");
        assert_eq!(decompressed, input);
    }
});
