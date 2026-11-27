//! Safe implementation of the MS-XCA LZNT1 chunk format.
//!
//! LZNT1 splits input into independent 4 KiB chunks. Each compressed chunk
//! contains groups of eight LSB-first token flags followed by literals or
//! 16-bit `(offset, length)` tokens. The token field split changes as output
//! advances through a chunk.

use crate::codec::CodecError;

const CHUNK_SIZE: usize = 0x1000;
const CHUNK_SIGNATURE: u16 = 0x3000;
const COMPRESSED_CHUNK: u16 = 0x8000;
const CHUNK_LENGTH_MASK: u16 = 0x0fff;
const TOKENS_PER_FLAG: usize = 8;
const MIN_MATCH: usize = 3;
const HASH_BITS: usize = 12;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN_STEPS: usize = 64;
const NO_POSITION: usize = usize::MAX;

/// Compresses `input` as an MS-XCA LZNT1 stream.
///
/// The encoder always uses independent 4096-byte chunks and stores a chunk
/// literally unless its compressed body is strictly smaller.
pub fn compress(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let chunk_count = input.len() / CHUNK_SIZE + usize::from(input.len() % CHUNK_SIZE != 0);
    let header_bytes = chunk_count
        .checked_mul(size_of::<u16>())
        .ok_or(CodecError::IntegerOverflow)?;
    let maximum_size = input
        .len()
        .checked_add(header_bytes)
        .ok_or(CodecError::IntegerOverflow)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(maximum_size)
        .map_err(|_| CodecError::AllocationFailed)?;

    for chunk in input.chunks(CHUNK_SIZE) {
        let compressed = compress_chunk(chunk)?;
        if compressed.len() < chunk.len() {
            write_chunk_header(&mut output, compressed.len(), true)?;
            output.extend_from_slice(&compressed);
        } else {
            write_chunk_header(&mut output, chunk.len(), false)?;
            output.extend_from_slice(chunk);
        }
    }

    Ok(output)
}

/// Decompresses an MS-XCA LZNT1 stream with strict output bounds.
///
/// Every chunk header, body boundary, token, back-reference, and 4 KiB
/// decompressed chunk boundary is validated before output is written.
pub fn decompress(
    input: &[u8],
    expected_size: usize,
    max_output_size: usize,
) -> Result<Vec<u8>, CodecError> {
    if expected_size > max_output_size {
        return Err(CodecError::ExpectedSizeExceedsLimit {
            expected: expected_size,
            limit: max_output_size,
        });
    }
    if expected_size > isize::MAX as usize {
        return Err(CodecError::ExpectedSizeTooLarge {
            expected: expected_size,
        });
    }

    let mut output = Vec::new();
    output
        .try_reserve_exact(expected_size)
        .map_err(|_| CodecError::AllocationFailed)?;

    let mut input_position = 0usize;
    while input_position < input.len() {
        let header = read_u16(input, &mut input_position, "LZNT1 chunk header")?;

        if header == 0 {
            if input_position != input.len() {
                return Err(CodecError::Truncated(
                    "data following LZNT1 end-of-buffer marker",
                ));
            }
            break;
        }

        if header & 0x7000 != CHUNK_SIGNATURE {
            return Err(CodecError::Truncated("invalid LZNT1 chunk signature"));
        }

        let body_size = usize::from(header & CHUNK_LENGTH_MASK)
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;
        let body_end = input_position
            .checked_add(body_size)
            .ok_or(CodecError::IntegerOverflow)?;
        if body_end > input.len() {
            return Err(CodecError::Truncated("LZNT1 chunk body"));
        }

        if header & COMPRESSED_CHUNK == 0 {
            append_literal_chunk(
                &mut output,
                &input[input_position..body_end],
                expected_size,
                max_output_size,
            )?;
            input_position = body_end;
        } else {
            decompress_chunk(
                input,
                &mut input_position,
                body_end,
                &mut output,
                expected_size,
                max_output_size,
            )?;
        }
    }

    if output.len() != expected_size {
        return Err(CodecError::OutputSizeMismatch {
            actual: output.len(),
            expected: expected_size,
        });
    }

    Ok(output)
}

fn compress_chunk(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let flag_bytes = input
        .len()
        .checked_add(TOKENS_PER_FLAG - 1)
        .and_then(|length| length.checked_div(TOKENS_PER_FLAG))
        .ok_or(CodecError::IntegerOverflow)?;
    let maximum_size = input
        .len()
        .checked_add(flag_bytes)
        .ok_or(CodecError::IntegerOverflow)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(maximum_size)
        .map_err(|_| CodecError::AllocationFailed)?;

    let mut finder = MatchFinder::new(input.len())?;
    let mut position = 0usize;
    while position < input.len() {
        let flag_position = output.len();
        output.push(0);
        let mut flags = 0u8;

        for flag_bit in 0..TOKENS_PER_FLAG {
            if position == input.len() {
                break;
            }

            let (length_mask, offset_shift) = token_layout(position);
            let maximum_length = input
                .len()
                .checked_sub(position)
                .ok_or(CodecError::IntegerOverflow)?
                .min(length_mask + MIN_MATCH);
            let current_match = finder.find(input, position, maximum_length);
            finder.insert(input, position);

            let next_is_longer = if let Some(current) = current_match {
                let next_match = position
                    .checked_add(1)
                    .filter(|&next| next < input.len())
                    .and_then(|next| {
                        let (next_length_mask, _) = token_layout(next);
                        let next_maximum_length = input
                            .len()
                            .checked_sub(next)?
                            .min(next_length_mask + MIN_MATCH);
                        finder.find(input, next, next_maximum_length)
                    });
                next_match.is_some_and(|next| next.length > current.length)
            } else {
                false
            };

            if let Some(found) = current_match.filter(|_| !next_is_longer) {
                let encoded_offset = found
                    .offset
                    .checked_sub(1)
                    .and_then(|offset| offset.checked_shl(offset_shift.into()))
                    .ok_or(CodecError::IntegerOverflow)?;
                let encoded_length = found
                    .length
                    .checked_sub(MIN_MATCH)
                    .ok_or(CodecError::IntegerOverflow)?;
                let token = encoded_offset
                    .checked_add(encoded_length)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or(CodecError::IntegerOverflow)?;

                output.extend_from_slice(&token.to_le_bytes());
                flags |= 1u8 << flag_bit;
                let match_end = position
                    .checked_add(found.length)
                    .ok_or(CodecError::IntegerOverflow)?;
                for dictionary_position in position + 1..match_end {
                    finder.insert(input, dictionary_position);
                }
                position = match_end;
            } else {
                output.push(input[position]);
                position = position.checked_add(1).ok_or(CodecError::IntegerOverflow)?;
            }
        }

        output[flag_position] = flags;
    }

    Ok(output)
}

#[derive(Clone, Copy)]
struct Match {
    offset: usize,
    length: usize,
}

struct MatchFinder {
    heads: Box<[usize]>,
    previous: Vec<usize>,
}

impl MatchFinder {
    fn new(input_length: usize) -> Result<Self, CodecError> {
        let mut heads = Vec::new();
        heads
            .try_reserve_exact(HASH_SIZE)
            .map_err(|_| CodecError::AllocationFailed)?;
        heads.resize(HASH_SIZE, NO_POSITION);

        let mut previous = Vec::new();
        previous
            .try_reserve_exact(input_length)
            .map_err(|_| CodecError::AllocationFailed)?;
        previous.resize(input_length, NO_POSITION);

        Ok(Self {
            heads: heads.into_boxed_slice(),
            previous,
        })
    }

    fn insert(&mut self, input: &[u8], position: usize) {
        let Some(hash) = hash_at(input, position) else {
            return;
        };
        self.previous[position] = self.heads[hash];
        self.heads[hash] = position;
    }

    fn find(&self, input: &[u8], position: usize, maximum_length: usize) -> Option<Match> {
        let maximum_length = maximum_length.min(input.len().checked_sub(position)?);
        let hash = hash_at(input, position)?;
        if maximum_length < MIN_MATCH || position == 0 {
            return None;
        }

        let mut candidate = self.heads[hash];
        let mut steps = 0usize;
        let mut best = None;

        // Hash chains are newest-first, preserving the old nearest-offset
        // tie-break while placing a hard bound on incompressible input work.
        while candidate != NO_POSITION && steps < MAX_CHAIN_STEPS {
            let offset = position.checked_sub(candidate)?;
            if input.get(candidate..candidate + MIN_MATCH)
                != input.get(position..position + MIN_MATCH)
            {
                candidate = self.previous[candidate];
                steps += 1;
                continue;
            }
            let mut length = MIN_MATCH;
            while length < maximum_length
                && input[position + length] == input[position + length - offset]
            {
                length += 1;
            }

            if best.is_none_or(|found: Match| length > found.length) {
                best = Some(Match { offset, length });
                if length == maximum_length {
                    break;
                }
            }
            candidate = self.previous[candidate];
            steps += 1;
        }

        best
    }
}

fn hash_at(input: &[u8], position: usize) -> Option<usize> {
    let bytes = input.get(position..position.checked_add(MIN_MATCH)?)?;
    let value = (u32::from(bytes[0]) << 16) ^ (u32::from(bytes[1]) << 8) ^ u32::from(bytes[2]);
    Some(value.wrapping_mul(2_654_435_761u32) as usize >> (u32::BITS as usize - HASH_BITS))
}

fn token_layout(output_position: usize) -> (usize, u8) {
    let mut length_mask = 0x0fffusize;
    let mut offset_shift = 12u8;
    let mut cursor = output_position.saturating_sub(1);

    while cursor >= 0x10 {
        length_mask >>= 1;
        offset_shift -= 1;
        cursor >>= 1;
    }

    (length_mask, offset_shift)
}

fn write_chunk_header(
    output: &mut Vec<u8>,
    body_size: usize,
    compressed: bool,
) -> Result<(), CodecError> {
    let stored_size = body_size
        .checked_sub(1)
        .and_then(|size| u16::try_from(size).ok())
        .filter(|size| *size <= CHUNK_LENGTH_MASK)
        .ok_or(CodecError::IntegerOverflow)?;
    let header = CHUNK_SIGNATURE | if compressed { COMPRESSED_CHUNK } else { 0 } | stored_size;
    output.extend_from_slice(&header.to_le_bytes());
    Ok(())
}

fn append_literal_chunk(
    output: &mut Vec<u8>,
    chunk: &[u8],
    expected_size: usize,
    max_output_size: usize,
) -> Result<(), CodecError> {
    if chunk.len() > CHUNK_SIZE {
        return Err(CodecError::OutputExceedsLimit {
            attempted: chunk.len(),
            limit: CHUNK_SIZE,
        });
    }

    let attempted = output
        .len()
        .checked_add(chunk.len())
        .ok_or(CodecError::IntegerOverflow)?;
    check_output_size(attempted, expected_size, max_output_size)?;
    output.extend_from_slice(chunk);
    Ok(())
}

fn decompress_chunk(
    input: &[u8],
    input_position: &mut usize,
    body_end: usize,
    output: &mut Vec<u8>,
    expected_size: usize,
    max_output_size: usize,
) -> Result<(), CodecError> {
    let chunk_start = output.len();

    while *input_position < body_end {
        let flags = read_u8_within(input, input_position, body_end, "LZNT1 compressed flag")?;
        let mut token_count = 0usize;

        for flag_bit in 0..TOKENS_PER_FLAG {
            if *input_position == body_end {
                break;
            }
            token_count += 1;

            if flags & (1u8 << flag_bit) == 0 {
                let literal = read_u8_within(input, input_position, body_end, "LZNT1 literal")?;
                check_chunk_growth(output.len() - chunk_start, 1)?;
                let attempted = output
                    .len()
                    .checked_add(1)
                    .ok_or(CodecError::IntegerOverflow)?;
                check_output_size(attempted, expected_size, max_output_size)?;
                output.push(literal);
                continue;
            }

            let token = read_u16_within(input, input_position, body_end, "LZNT1 compressed token")?;
            let produced = output
                .len()
                .checked_sub(chunk_start)
                .ok_or(CodecError::IntegerOverflow)?;
            let (length_mask, offset_shift) = token_layout(produced);
            let length = usize::from(token & length_mask as u16)
                .checked_add(MIN_MATCH)
                .ok_or(CodecError::IntegerOverflow)?;
            let offset = usize::from(token >> offset_shift)
                .checked_add(1)
                .ok_or(CodecError::IntegerOverflow)?;

            if offset > produced {
                return Err(CodecError::InvalidOffset { offset, produced });
            }

            check_chunk_growth(produced, length)?;
            let attempted = output
                .len()
                .checked_add(length)
                .ok_or(CodecError::IntegerOverflow)?;
            check_output_size(attempted, expected_size, max_output_size)?;

            // The source moves as output grows, intentionally supporting
            // matches whose length exceeds their offset.
            for _ in 0..length {
                let source = output
                    .len()
                    .checked_sub(offset)
                    .ok_or(CodecError::IntegerOverflow)?;
                let byte = output[source];
                output.push(byte);
            }
        }

        if token_count == 0 {
            return Err(CodecError::Truncated("LZNT1 flag group token"));
        }
    }

    if output.len() == chunk_start {
        return Err(CodecError::Truncated("empty LZNT1 compressed chunk"));
    }
    Ok(())
}

fn check_chunk_growth(produced: usize, additional: usize) -> Result<(), CodecError> {
    let attempted = produced
        .checked_add(additional)
        .ok_or(CodecError::IntegerOverflow)?;
    if attempted > CHUNK_SIZE {
        return Err(CodecError::OutputExceedsLimit {
            attempted,
            limit: CHUNK_SIZE,
        });
    }
    Ok(())
}

fn check_output_size(
    attempted: usize,
    expected_size: usize,
    max_output_size: usize,
) -> Result<(), CodecError> {
    if attempted > max_output_size {
        return Err(CodecError::OutputExceedsLimit {
            attempted,
            limit: max_output_size,
        });
    }
    if attempted > expected_size {
        return Err(CodecError::OutputExceedsExpected {
            attempted,
            expected: expected_size,
        });
    }
    Ok(())
}

fn read_u16(
    input: &[u8],
    position: &mut usize,
    component: &'static str,
) -> Result<u16, CodecError> {
    read_u16_within(input, position, input.len(), component)
}

fn read_u8_within(
    input: &[u8],
    position: &mut usize,
    end: usize,
    component: &'static str,
) -> Result<u8, CodecError> {
    if *position >= end {
        return Err(CodecError::Truncated(component));
    }
    let value = input
        .get(*position)
        .copied()
        .ok_or(CodecError::Truncated(component))?;
    *position = position.checked_add(1).ok_or(CodecError::IntegerOverflow)?;
    Ok(value)
}

fn read_u16_within(
    input: &[u8],
    position: &mut usize,
    end: usize,
    component: &'static str,
) -> Result<u16, CodecError> {
    let value_end = position
        .checked_add(size_of::<u16>())
        .ok_or(CodecError::IntegerOverflow)?;
    if value_end > end {
        return Err(CodecError::Truncated(component));
    }
    let bytes: [u8; 2] = input
        .get(*position..value_end)
        .ok_or(CodecError::Truncated(component))?
        .try_into()
        .map_err(|_| CodecError::Truncated(component))?;
    *position = value_end;
    Ok(u16::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{CHUNK_SIZE, CodecError, compress, decompress};

    const LITERAL_GOLDEN: &[u8] = &[0x03, 0x30, b'A', b'B', b'C', b'D'];
    const MATCH_GOLDEN: &[u8] = &[0x05, 0xb0, 0x08, b'A', b'B', b'C', 0x03, 0x20];

    #[test]
    fn python_golden_streams_encode_and_decode() {
        assert_eq!(decompress(LITERAL_GOLDEN, 4, 4), Ok(b"ABCD".to_vec()));
        assert_eq!(decompress(MATCH_GOLDEN, 9, 9), Ok(b"ABCABCABC".to_vec()));
        assert_eq!(compress(b"ABCD"), Ok(LITERAL_GOLDEN.to_vec()));
        assert_eq!(compress(b"ABCABCABC"), Ok(MATCH_GOLDEN.to_vec()));
    }

    #[test]
    fn microsoft_lznt1_example_decodes() {
        let encoded = [
            0x38, 0xb0, 0x88, 0x46, 0x23, 0x20, 0x00, 0x20, 0x47, 0x20, 0x41, 0x00, 0x10, 0xa2,
            0x47, 0x01, 0xa0, 0x45, 0x20, 0x44, 0x00, 0x08, 0x45, 0x01, 0x50, 0x79, 0x00, 0xc0,
            0x45, 0x20, 0x05, 0x24, 0x13, 0x88, 0x05, 0xb4, 0x02, 0x4a, 0x44, 0xef, 0x03, 0x58,
            0x02, 0x8c, 0x09, 0x16, 0x01, 0x48, 0x45, 0x00, 0xbe, 0x00, 0x9e, 0x00, 0x04, 0x01,
            0x18, 0x90, 0x00,
        ];
        let plain = b"F# F# G A A G F# E D D E F# F# E E F# F# G A A G F# E D D E F# E D D E E F# D E F# G F# D E F# G F# E D E A F# F# G A A G F# E D D E F# E D D\0";

        assert_eq!(plain.len(), 142);
        assert_eq!(
            decompress(&encoded, plain.len(), plain.len()),
            Ok(plain.to_vec())
        );
    }

    #[test]
    fn empty_stream_and_optional_terminal_decode() {
        assert_eq!(compress(b""), Ok(Vec::new()));
        assert_eq!(decompress(b"", 0, 0), Ok(Vec::new()));
        assert_eq!(decompress(&[0, 0], 0, 0), Ok(Vec::new()));
    }

    #[test]
    fn overlapping_match_copies_from_growing_chunk() {
        let encoded = [0x03, 0xb0, 0x02, b'a', 0x02, 0x00];
        assert_eq!(decompress(&encoded, 6, 6), Ok(b"aaaaaa".to_vec()));

        let plain = vec![b'a'; CHUNK_SIZE];
        let encoded = compress(&plain).expect("repeated chunk should compress");
        assert_eq!(decompress(&encoded, plain.len(), plain.len()), Ok(plain));
    }

    #[test]
    fn round_trips_cover_4k_boundaries_and_multiple_chunks() {
        let inputs = [
            Vec::new(),
            vec![0],
            (0u8..=u8::MAX).collect(),
            vec![b'A'; CHUNK_SIZE - 1],
            vec![b'A'; CHUNK_SIZE],
            vec![b'A'; CHUNK_SIZE + 1],
            pseudo_random(CHUNK_SIZE * 3 + 137),
        ];

        for plain in inputs {
            let encoded = compress(&plain).expect("compression should succeed");
            assert_eq!(
                decompress(&encoded, plain.len(), plain.len()),
                Ok(plain.clone()),
                "round trip failed for {} bytes",
                plain.len()
            );

            for (signature, body_size, _) in chunk_headers(&encoded) {
                assert_eq!(signature, 3);
                assert!((1..=CHUNK_SIZE).contains(&body_size));
            }
        }
    }

    #[test]
    fn exact_boundary_uses_independent_chunks() {
        let plain = vec![b'Z'; CHUNK_SIZE + 1];
        let encoded = compress(&plain).expect("compression should succeed");
        let headers = chunk_headers(&encoded);

        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1, 1);
        assert!(!headers[1].2, "one-byte tail must be literal");
        assert_eq!(decompress(&encoded, plain.len(), plain.len()), Ok(plain));
    }

    #[test]
    fn compression_is_deterministic() {
        for plain in [
            b"ABCABCABC".to_vec(),
            vec![0x5a; CHUNK_SIZE + 17],
            pseudo_random(CHUNK_SIZE * 2 + 31),
        ] {
            let first = compress(&plain).expect("first compression should succeed");
            let second = compress(&plain).expect("second compression should succeed");
            assert_eq!(first, second);
        }
    }

    #[test]
    fn malformed_headers_chunks_and_tokens_are_rejected() {
        let malformed: &[(&[u8], usize)] = &[
            (&[0x03], 0),
            (&[0x00, 0x20, 0x00], 1),
            (&[0x03, 0x30, b'A', b'B'], 4),
            (&[0x01, 0xb0, 0x01, 0x00], 3),
            (&[0x02, 0xb0, 0x01, 0x00, 0x00], 3),
            (&[0x00, 0xb0, 0x00], 0),
            (&[0x00, 0x00, 0xff], 0),
        ];

        for &(encoded, expected_size) in malformed {
            assert!(
                decompress(encoded, expected_size, expected_size).is_err(),
                "accepted malformed stream {encoded:02x?}"
            );
        }
    }

    #[test]
    fn matches_cannot_cross_chunk_boundaries() {
        let encoded = [
            0x00, 0x30, b'A', // one-byte literal chunk
            0x02, 0xb0, 0x01, 0x00, 0x00, // match before second chunk output
        ];
        assert!(matches!(
            decompress(&encoded, 4, 4),
            Err(CodecError::InvalidOffset {
                offset: 1,
                produced: 0
            })
        ));
    }

    #[test]
    fn decompressed_chunks_cannot_exceed_4096_bytes() {
        // One literal followed by an offset=1, length=4096 match.
        let encoded = [0x03, 0xb0, 0x02, b'A', 0xfd, 0x0f];
        assert!(decompress(&encoded, CHUNK_SIZE + 1, CHUNK_SIZE + 1).is_err());
    }

    #[test]
    fn expected_size_and_output_limit_are_enforced() {
        let one_literal = [0x00, 0x30, b'A'];
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

    fn chunk_headers(encoded: &[u8]) -> Vec<(u16, usize, bool)> {
        let mut headers = Vec::new();
        let mut position = 0usize;
        while position < encoded.len() {
            let header = u16::from_le_bytes([encoded[position], encoded[position + 1]]);
            position += 2;
            if header == 0 {
                break;
            }
            let body_size = usize::from(header & 0x0fff) + 1;
            headers.push(((header >> 12) & 0x7, body_size, header & 0x8000 != 0));
            position += body_size;
        }
        assert_eq!(position, encoded.len());
        headers
    }

    fn pseudo_random(length: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9u32;
        (0..length)
            .map(|index| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state as u8) ^ (index as u8)
            })
            .collect()
    }
}
