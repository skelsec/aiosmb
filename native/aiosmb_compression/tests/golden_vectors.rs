use aiosmb_compression::{CodecError, compress, decompress};
use proptest::prelude::*;

const LITERAL_GOLDEN: &[u8] = &[
    0x3f, 0x00, 0x00, 0x00, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l',
    b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
];

const LONG_MATCH_GOLDEN: &[u8] = &[
    0xff, 0xff, 0xff, 0x1f, b'a', b'b', b'c', 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01,
];

const OVERLAPPING_MATCH_GOLDEN: &[u8] = &[0xff, 0xff, 0xff, 0x7f, b'a', 0x02, 0x00];

#[test]
fn microsoft_literal_golden_vector() {
    let plain = b"abcdefghijklmnopqrstuvwxyz";
    assert_eq!(
        decompress(LITERAL_GOLDEN, plain.len(), plain.len()),
        Ok(plain.to_vec())
    );
    assert_eq!(compress(plain), Ok(LITERAL_GOLDEN.to_vec()));
}

#[test]
fn microsoft_long_match_golden_vector() {
    let plain = b"abc".repeat(100);
    assert_eq!(
        decompress(LONG_MATCH_GOLDEN, plain.len(), plain.len()),
        Ok(plain.clone())
    );
    assert_eq!(compress(&plain), Ok(LONG_MATCH_GOLDEN.to_vec()));
}

#[test]
fn overlapping_back_reference_golden_vector() {
    let plain = b"aaaaaa";
    assert_eq!(
        decompress(OVERLAPPING_MATCH_GOLDEN, plain.len(), plain.len()),
        Ok(plain.to_vec())
    );
    assert_eq!(compress(plain), Ok(OVERLAPPING_MATCH_GOLDEN.to_vec()));
}

#[test]
fn paired_length_nibbles_are_shared_low_then_high() {
    // literal "a", then (offset=1, length=10), then (offset=1, length=11).
    // The first match owns the low nibble and the second consumes the high
    // nibble from the same 0x10 byte.
    let encoded = [0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x10, 0x07, 0x00];
    assert_eq!(decompress(&encoded, 22, 22), Ok(vec![b'a'; 22]));

    // Two separate runs force the compressor to emit two extended matches.
    let plain = [vec![b'a'; 11], vec![b'!'], vec![b'b'; 12]].concat();
    let encoded = [
        0xff, 0xff, 0xff, 0x4f, b'a', 0x07, 0x00, 0x10, b'!', b'b', 0x07, 0x00,
    ];
    assert_eq!(compress(&plain), Ok(encoded.to_vec()));
    assert_eq!(decompress(&encoded, plain.len(), plain.len()), Ok(plain));
}

#[test]
fn extended_length_boundaries_encode_and_decode() {
    let vectors: &[(&[u8], usize)] = &[
        (&[0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0e], 25),
        (&[0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0x00], 26),
        (&[0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0xfe], 280),
        (
            &[
                0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0xff, 0x15, 0x01,
            ],
            281,
        ),
        (
            &[
                0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0xff, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x00,
            ],
            65_540,
        ),
    ];

    for &(encoded, plain_length) in vectors {
        let plain = vec![b'a'; plain_length];
        assert_eq!(
            decompress(encoded, plain_length, plain_length),
            Ok(plain.clone())
        );
        assert_eq!(compress(&plain), Ok(encoded.to_vec()));
    }
}

#[test]
fn empty_and_exact_flag_group_terminal_vectors() {
    assert_eq!(compress(b""), Ok(vec![0xff; 4]));
    assert_eq!(decompress(&[0xff; 4], 0, 0), Ok(Vec::new()));

    let plain: Vec<u8> = (0u8..32).collect();
    let mut encoded = vec![0, 0, 0, 0];
    encoded.extend_from_slice(&plain);
    encoded.extend_from_slice(&[0xff; 4]);
    assert_eq!(compress(&plain), Ok(encoded.clone()));
    assert_eq!(decompress(&encoded, plain.len(), plain.len()), Ok(plain));
}

#[test]
fn incompressible_input_is_deterministic() {
    let plain: Vec<u8> = (0u8..=u8::MAX).collect();
    let first = compress(&plain).expect("compression should succeed");
    let second = compress(&plain).expect("compression should be deterministic");
    assert_eq!(first, second);
    assert_eq!(first.len(), plain.len() + (plain.len() / 32 + 1) * 4);
    assert_eq!(decompress(&first, plain.len(), plain.len()), Ok(plain));
}

#[test]
fn deterministic_round_trips_cover_windows_and_flag_boundaries() {
    for length in [
        0usize, 1, 2, 3, 9, 10, 24, 25, 31, 32, 33, 279, 280, 8191, 8192, 8193, 20_000,
    ] {
        let mut state = 0x9e37_79b9u32;
        let plain: Vec<u8> = (0..length)
            .map(|index| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state as u8) ^ (index as u8)
            })
            .collect();
        let encoded = compress(&plain).expect("compression should succeed");
        assert_eq!(
            compress(&plain).expect("second compression should succeed"),
            encoded
        );
        assert_eq!(
            decompress(&encoded, plain.len(), plain.len()),
            Ok(plain),
            "failed at input length {length}"
        );
    }
}

#[test]
fn malformed_and_truncated_streams_are_rejected() {
    let malformed: &[&[u8]] = &[
        &[],
        &[0xff],
        &[0x00, 0x00, 0x00, 0x00],
        &[0xff, 0xff, 0xff, 0xff, 0x00],
        &[0xff, 0xff, 0xff, 0xff, 0x00, 0x00],
        &[0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00],
        &[
            0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0xff, 0x01, 0x00,
        ],
        &[
            0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0xff, 0x00, 0x00,
        ],
    ];

    for encoded in malformed {
        assert!(
            decompress(encoded, 1, 1).is_err(),
            "accepted malformed stream {encoded:02x?}"
        );
    }
}

#[test]
fn expected_size_and_output_limit_are_strict() {
    let one_literal = [0xff, 0xff, 0xff, 0x7f, b'a'];
    assert!(matches!(
        decompress(&one_literal, 0, 0),
        Err(CodecError::OutputExceedsLimit { .. })
    ));
    assert!(matches!(
        decompress(&one_literal, 2, 2),
        Err(CodecError::OutputSizeMismatch {
            actual: 1,
            expected: 2
        })
    ));
    assert!(matches!(
        decompress(&one_literal, 2, 1),
        Err(CodecError::ExpectedSizeExceedsLimit {
            expected: 2,
            limit: 1
        })
    ));
}

#[test]
fn oversized_extended_length_cannot_escape_output_bounds() {
    let encoded = [
        0xff, 0xff, 0xff, 0x7f, b'a', 0x07, 0x00, 0x0f, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];
    assert!(decompress(&encoded, 1, 1).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_byte_sequences_round_trip(
        plain in prop::collection::vec(any::<u8>(), 0..65_536)
    ) {
        let encoded = compress(&plain).expect("bounded property input should compress");
        let decoded = decompress(&encoded, plain.len(), plain.len())
            .expect("the encoder must always produce a valid bounded stream");
        prop_assert_eq!(decoded, plain);
    }
}
