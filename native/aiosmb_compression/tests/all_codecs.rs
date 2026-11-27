use aiosmb_compression::{lz4, lz77_huffman, lznt1};
use proptest::prelude::*;

#[test]
fn lznt1_decodes_reference_vectors() {
    assert_eq!(
        lznt1::decompress(&hex("033041424344"), 4, 4).unwrap(),
        b"ABCD"
    );
    assert_eq!(
        lznt1::decompress(&hex("05b0084142430320"), 9, 9).unwrap(),
        b"ABCABCABC"
    );
}

#[test]
fn lz4_decodes_raw_literal_vector() {
    assert_eq!(lz4::decompress(b"\x40ABCD", 4, 4).unwrap(), b"ABCD");
}

#[test]
fn xpress_huffman_decodes_windows_server_2025_vector() {
    let encoded = hex(concat!(
        "0000000000000000000000000000000000000000000030000000000000000000",
        "0000000000000000000000000000000040555504450040440045554500000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0500000000000000000000000000000000000000000000000000000000000000",
        "0000000000000040000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "78240d5bcd74844961a307e67eb3c53ec0770000ffdfff",
    ));
    let expected = (b"aiosmb-huffman-windows-vector-".repeat(4096))[..65536].to_vec();

    assert_eq!(
        lz77_huffman::decompress(&encoded, expected.len(), expected.len()).unwrap(),
        expected,
    );
}

#[test]
fn every_codec_rejects_output_above_the_limit() {
    let input = b"repetitive repetitive repetitive repetitive";

    let compressed = lznt1::compress(input).unwrap();
    assert!(lznt1::decompress(&compressed, input.len(), input.len() - 1).is_err());

    let compressed = lz77_huffman::compress(input).unwrap();
    assert!(lz77_huffman::decompress(&compressed, input.len(), input.len() - 1).is_err());

    let compressed = lz4::compress(input).unwrap();
    assert!(lz4::decompress(&compressed, input.len(), input.len() - 1).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn arbitrary_inputs_round_trip(data in proptest::collection::vec(any::<u8>(), 0..=16384)) {
        let compressed = lznt1::compress(&data).unwrap();
        let decoded = lznt1::decompress(&compressed, data.len(), data.len()).unwrap();
        prop_assert_eq!(decoded.as_slice(), data.as_slice());

        let compressed = lz77_huffman::compress(&data).unwrap();
        let decoded =
            lz77_huffman::decompress(&compressed, data.len(), data.len()).unwrap();
        prop_assert_eq!(decoded.as_slice(), data.as_slice());

        let compressed = lz4::compress(&data).unwrap();
        let decoded = lz4::decompress(&compressed, data.len(), data.len()).unwrap();
        prop_assert_eq!(decoded.as_slice(), data.as_slice());
    }
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_hex_digit(pair[0]);
            let low = decode_hex_digit(pair[1]);
            (high << 4) | low
        })
        .collect()
}

fn decode_hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("test vector must contain hexadecimal digits"),
    }
}
