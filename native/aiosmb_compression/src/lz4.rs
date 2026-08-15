//! Safe implementation of the raw LZ4 block format.
//!
//! This is the block format described by the LZ4 specification: it has no
//! frame header, checksums, content-size field, or block-size field. Callers
//! must supply the exact decoded size and an independent output limit.

use crate::codec::CodecError;

const MIN_MATCH: usize = 4;
const MAX_OFFSET: usize = u16::MAX as usize;
const LAST_LITERALS: usize = 5;
const MATCH_FIND_LIMIT: usize = 12;
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN_STEPS: usize = 64;
const NO_POSITION: usize = usize::MAX;

/// Compresses `input` as a deterministic raw LZ4 block.
///
/// The emitted block follows the LZ4 end-of-block restrictions: the final
/// sequence is literal-only, at least the final five input bytes are emitted
/// as literals when a match is present, and the final match starts at least
/// twelve bytes before the end of the input.
pub fn compress(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let capacity = input
        .len()
        .checked_add(input.len() / 255)
        .and_then(|value| value.checked_add(16))
        .ok_or(CodecError::IntegerOverflow)?;
    let mut output = Output::with_capacity(capacity)?;

    if input.len() < MATCH_FIND_LIMIT {
        write_sequence(&mut output, input, None)?;
        return Ok(output.finish());
    }

    let mut finder = MatchFinder::new(input.len())?;

    let mut anchor = 0usize;
    let mut position = 0usize;
    let search_limit = input
        .len()
        .checked_sub(MATCH_FIND_LIMIT)
        .ok_or(CodecError::IntegerOverflow)?;

    while position <= search_limit {
        let maximum_length = input
            .len()
            .checked_sub(position)
            .and_then(|remaining| remaining.checked_sub(LAST_LITERALS))
            .ok_or(CodecError::IntegerOverflow)?;

        if let Some((offset, match_length)) = finder.find(input, position, maximum_length) {
            write_sequence(
                &mut output,
                &input[anchor..position],
                Some((offset, match_length)),
            )?;

            let match_end = position
                .checked_add(match_length)
                .ok_or(CodecError::IntegerOverflow)?;
            for dictionary_position in position..match_end {
                finder.insert(input, dictionary_position);
            }
            position = match_end;
            anchor = match_end;
        } else {
            finder.insert(input, position);
            position = position.checked_add(1).ok_or(CodecError::IntegerOverflow)?;
        }
    }

    write_sequence(&mut output, &input[anchor..], None)?;
    Ok(output.finish())
}

/// Decompresses a raw LZ4 block with strict output bounds.
///
/// `expected_size` is exact, not a hint. Decoding fails before writing a
/// sequence that would exceed either `expected_size` or `max_output_size`.
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

    let mut position = 0usize;
    loop {
        let token = read_u8(input, &mut position, "LZ4 sequence token")?;

        let literal_length = read_length(
            input,
            &mut position,
            usize::from(token >> 4),
            "LZ4 literal length",
        )?;
        let literal_end = position
            .checked_add(literal_length)
            .ok_or(CodecError::IntegerOverflow)?;
        let literals = input
            .get(position..literal_end)
            .ok_or(CodecError::Truncated("LZ4 literals"))?;
        let attempted = output
            .len()
            .checked_add(literal_length)
            .ok_or(CodecError::IntegerOverflow)?;
        check_output_size(attempted, expected_size, max_output_size)?;
        output.extend_from_slice(literals);
        position = literal_end;

        // A valid block terminates with a literal-only sequence. The low
        // token nibble has no meaning for that final sequence.
        if position == input.len() {
            if output.len() != expected_size {
                return Err(CodecError::OutputSizeMismatch {
                    actual: output.len(),
                    expected: expected_size,
                });
            }
            return Ok(output);
        }

        let offset = read_u16(input, &mut position, "LZ4 match offset")?;
        let offset = usize::from(offset);
        if offset == 0 || offset > output.len() {
            return Err(CodecError::InvalidOffset {
                offset,
                produced: output.len(),
            });
        }

        let encoded_match_length = read_length(
            input,
            &mut position,
            usize::from(token & 0x0f),
            "LZ4 match length",
        )?;
        let match_length = encoded_match_length
            .checked_add(MIN_MATCH)
            .ok_or(CodecError::IntegerOverflow)?;
        let attempted = output
            .len()
            .checked_add(match_length)
            .ok_or(CodecError::IntegerOverflow)?;
        check_output_size(attempted, expected_size, max_output_size)?;

        // The source index is recomputed after every push. This intentionally
        // permits the overlapping back-references required by LZ4.
        for _ in 0..match_length {
            let source = output
                .len()
                .checked_sub(offset)
                .ok_or(CodecError::IntegerOverflow)?;
            let byte = output[source];
            output.push(byte);
        }
    }
}

fn write_sequence(
    output: &mut Output,
    literals: &[u8],
    match_data: Option<(usize, usize)>,
) -> Result<(), CodecError> {
    let (offset, match_length) = match_data.unwrap_or((0, MIN_MATCH));
    let encoded_match_length = match_length
        .checked_sub(MIN_MATCH)
        .ok_or(CodecError::IntegerOverflow)?;
    let literal_nibble =
        u8::try_from(literals.len().min(15)).map_err(|_| CodecError::IntegerOverflow)?;
    let match_nibble = if match_data.is_some() {
        u8::try_from(encoded_match_length.min(15)).map_err(|_| CodecError::IntegerOverflow)?
    } else {
        0
    };

    output.push((literal_nibble << 4) | match_nibble)?;
    if literals.len() >= 15 {
        write_length_extension(output, literals.len() - 15)?;
    }
    output.extend_from_slice(literals)?;

    if match_data.is_none() {
        return Ok(());
    }
    if offset == 0 || offset > MAX_OFFSET {
        return Err(CodecError::InvalidOffset {
            offset,
            produced: 0,
        });
    }
    output.extend_from_slice(
        &u16::try_from(offset)
            .map_err(|_| CodecError::IntegerOverflow)?
            .to_le_bytes(),
    )?;
    if encoded_match_length >= 15 {
        write_length_extension(output, encoded_match_length - 15)?;
    }
    Ok(())
}

fn write_length_extension(output: &mut Output, mut length: usize) -> Result<(), CodecError> {
    while length >= 255 {
        output.push(255)?;
        length = length.checked_sub(255).ok_or(CodecError::IntegerOverflow)?;
    }
    output.push(u8::try_from(length).map_err(|_| CodecError::IntegerOverflow)?)
}

fn read_length(
    input: &[u8],
    position: &mut usize,
    initial: usize,
    component: &'static str,
) -> Result<usize, CodecError> {
    if initial != 15 {
        return Ok(initial);
    }

    let mut length = initial;
    loop {
        let extension = usize::from(read_u8(input, position, component)?);
        length = length
            .checked_add(extension)
            .ok_or(CodecError::IntegerOverflow)?;
        if extension != 255 {
            return Ok(length);
        }
    }
}

fn read_u8(input: &[u8], position: &mut usize, component: &'static str) -> Result<u8, CodecError> {
    let value = input
        .get(*position)
        .copied()
        .ok_or(CodecError::Truncated(component))?;
    *position = position.checked_add(1).ok_or(CodecError::IntegerOverflow)?;
    Ok(value)
}

fn read_u16(
    input: &[u8],
    position: &mut usize,
    component: &'static str,
) -> Result<u16, CodecError> {
    let end = position.checked_add(2).ok_or(CodecError::IntegerOverflow)?;
    let bytes: [u8; 2] = input
        .get(*position..end)
        .ok_or(CodecError::Truncated(component))?
        .try_into()
        .map_err(|_| CodecError::Truncated(component))?;
    *position = end;
    Ok(u16::from_le_bytes(bytes))
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

struct Output {
    bytes: Vec<u8>,
}

impl Output {
    fn with_capacity(capacity: usize) -> Result<Self, CodecError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| CodecError::AllocationFailed)?;
        Ok(Self { bytes })
    }

    fn push(&mut self, value: u8) -> Result<(), CodecError> {
        self.bytes
            .try_reserve(1)
            .map_err(|_| CodecError::AllocationFailed)?;
        self.bytes.push(value);
        Ok(())
    }

    fn extend_from_slice(&mut self, value: &[u8]) -> Result<(), CodecError> {
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| CodecError::AllocationFailed)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct MatchFinder {
    heads: Vec<usize>,
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

        Ok(Self { heads, previous })
    }

    fn find(&self, input: &[u8], position: usize, maximum_length: usize) -> Option<(usize, usize)> {
        if maximum_length < MIN_MATCH {
            return None;
        }

        let mut candidate = self.heads[hash_at(input, position)?];
        let mut best = None;
        let mut steps = 0usize;

        while candidate != NO_POSITION && steps < MAX_CHAIN_STEPS {
            let offset = position.checked_sub(candidate)?;
            if offset > MAX_OFFSET {
                break;
            }

            if input.get(candidate..candidate.checked_add(MIN_MATCH)?)
                == input.get(position..position.checked_add(MIN_MATCH)?)
            {
                let mut length = MIN_MATCH;
                while length < maximum_length
                    && input.get(candidate.checked_add(length)?)
                        == input.get(position.checked_add(length)?)
                {
                    length = length.checked_add(1)?;
                }

                if best.is_none_or(|(_, best_length)| length > best_length) {
                    best = Some((offset, length));
                    if length == maximum_length {
                        break;
                    }
                }
            }

            candidate = *self.previous.get(candidate)?;
            steps = steps.checked_add(1)?;
        }
        best
    }

    fn insert(&mut self, input: &[u8], position: usize) {
        let Some(hash) = hash_at(input, position) else {
            return;
        };
        self.previous[position] = self.heads[hash];
        self.heads[hash] = position;
    }
}

fn hash_at(input: &[u8], position: usize) -> Option<usize> {
    let bytes = input.get(position..position.checked_add(MIN_MATCH)?)?;
    let value = u32::from_le_bytes(bytes.try_into().ok()?);
    Some((value.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize)
}

#[cfg(test)]
mod tests {
    use super::{CodecError, compress, decompress};

    #[test]
    fn simple_raw_block_vectors_decode() {
        // The empty and literal-only encodings are the canonical LZ4 block
        // representations produced by the reference encoder.
        assert_eq!(decompress(&[0x00], 0, 0), Ok(Vec::new()));
        assert_eq!(decompress(b"\x50hello", 5, 5), Ok(b"hello".to_vec()));

        // One literal, a 19-byte offset-one overlapping match, and the five
        // trailing literals required by the block-format restrictions.
        let repeated = [
            0x1f, b'a', 0x01, 0x00, 0x00, 0x50, b'a', b'a', b'a', b'a', b'a',
        ];
        assert_eq!(decompress(&repeated, 25, 25), Ok(vec![b'a'; 25]));
    }

    #[test]
    fn compressor_emits_known_literal_blocks() {
        assert_eq!(compress(b""), Ok(vec![0x00]));
        assert_eq!(compress(b"hello"), Ok(b"\x50hello".to_vec()));

        let input: Vec<u8> = (0u8..20).collect();
        let mut expected = vec![0xf0, 0x05];
        expected.extend_from_slice(&input);
        assert_eq!(compress(&input), Ok(expected));
    }

    #[test]
    fn extended_literal_lengths_decode() {
        for length in [15usize, 16, 269, 270, 271, 525] {
            let literals: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let mut encoded = vec![0xf0];
            append_extension(&mut encoded, length - 15);
            encoded.extend_from_slice(&literals);
            assert_eq!(
                decompress(&encoded, length, length),
                Ok(literals),
                "literal length {length}"
            );
        }
    }

    #[test]
    fn extended_match_lengths_and_overlap_decode() {
        for match_length in [19usize, 20, 273, 274, 275, 529] {
            let mut encoded = vec![0x1f, b'x', 0x01, 0x00];
            append_extension(&mut encoded, match_length - 19);
            encoded.extend_from_slice(&[0x50, b'x', b'x', b'x', b'x', b'x']);
            let expected_size = 1 + match_length + 5;
            assert_eq!(
                decompress(&encoded, expected_size, expected_size),
                Ok(vec![b'x'; expected_size]),
                "match length {match_length}"
            );
        }
    }

    #[test]
    fn nontrivial_overlap_repeats_the_source_pattern() {
        let encoded = [
            0x4c, b'a', b'b', b'c', b'd', 0x04, 0x00, 0x50, b'a', b'b', b'c', b'd', b'a',
        ];
        assert_eq!(
            decompress(&encoded, 25, 25),
            Ok(b"abcdabcdabcdabcdabcdabcda".to_vec())
        );
    }

    #[test]
    fn maximum_offset_is_accepted() {
        let literals = vec![b'z'; u16::MAX as usize];
        let mut encoded = vec![0xf0];
        append_extension(&mut encoded, literals.len() - 15);
        encoded.extend_from_slice(&literals);
        encoded.extend_from_slice(&u16::MAX.to_le_bytes());
        encoded.extend_from_slice(&[0x80, b'z', b'z', b'z', b'z', b'z', b'z', b'z', b'z']);

        let expected_size = literals.len() + 4 + 8;
        let mut expected = literals;
        expected.extend_from_slice(&[b'z'; 12]);
        assert_eq!(
            decompress(&encoded, expected_size, expected_size),
            Ok(expected)
        );
    }

    #[test]
    fn zero_and_out_of_history_offsets_are_rejected() {
        assert!(matches!(
            decompress(&[0x00, 0x00, 0x00], 4, 4),
            Err(CodecError::InvalidOffset {
                offset: 0,
                produced: 0
            })
        ));
        assert!(matches!(
            decompress(&[0x10, b'a', 0x02, 0x00], 5, 5),
            Err(CodecError::InvalidOffset {
                offset: 2,
                produced: 1
            })
        ));
    }

    #[test]
    fn truncated_components_are_rejected() {
        let malformed: &[&[u8]] = &[
            &[],
            &[0xf0],
            &[0xf0, 0xff],
            &[0xf0, 0x01, b'a'],
            &[0x00, 0x01],
            &[0x0f, 0x01, 0x00],
            &[0x0f, 0x01, 0x00, 0xff],
            // A match cannot be the final sequence in a standard LZ4 block.
            &[0x10, b'a', 0x01, 0x00],
        ];

        for encoded in malformed {
            assert!(
                decompress(encoded, 32, 32).is_err(),
                "accepted truncated block {encoded:02x?}"
            );
        }
    }

    #[test]
    fn expected_size_and_output_limit_are_enforced() {
        assert!(matches!(
            decompress(b"\x10a", 0, 0),
            Err(CodecError::OutputExceedsLimit {
                attempted: 1,
                limit: 0
            })
        ));
        assert!(matches!(
            decompress(b"\x10a", 0, 1),
            Err(CodecError::OutputExceedsExpected {
                attempted: 1,
                expected: 0
            })
        ));
        assert!(matches!(
            decompress(b"\x10a", 2, 2),
            Err(CodecError::OutputSizeMismatch {
                actual: 1,
                expected: 2
            })
        ));
        assert!(matches!(
            decompress(b"\x10a", 2, 1),
            Err(CodecError::ExpectedSizeExceedsLimit {
                expected: 2,
                limit: 1
            })
        ));

        let match_overflow = [0x10, b'a', 0x01, 0x00, 0x00];
        assert!(matches!(
            decompress(&match_overflow, 4, 4),
            Err(CodecError::OutputExceedsLimit {
                attempted: 5,
                limit: 4
            })
        ));
    }

    #[test]
    fn excessive_declared_size_is_rejected_before_allocation() {
        let expected = (isize::MAX as usize) + 1;
        assert_eq!(
            decompress(&[0x00], expected, expected),
            Err(CodecError::ExpectedSizeTooLarge { expected })
        );
    }

    #[test]
    fn compression_is_deterministic() {
        let input = b"the quick brown fox jumps over the quick brown fox";
        let first = compress(input).expect("compression should succeed");
        let second = compress(input).expect("compression should succeed");
        assert_eq!(first, second);
    }

    #[test]
    fn round_trips_boundaries_and_input_classes() {
        for length in [
            0usize, 1, 3, 4, 5, 11, 12, 13, 14, 15, 16, 19, 20, 254, 255, 256, 269, 270, 271, 4096,
            65_535, 65_536, 70_000,
        ] {
            let repeated = vec![b'q'; length];
            round_trip(&repeated);

            let mut state = 0x9e37_79b9u32;
            let mixed: Vec<u8> = (0..length)
                .map(|index| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    (state as u8) ^ (index as u8)
                })
                .collect();
            round_trip(&mixed);
        }
    }

    fn append_extension(output: &mut Vec<u8>, mut length: usize) {
        while length >= 255 {
            output.push(255);
            length -= 255;
        }
        output.push(length as u8);
    }

    fn round_trip(input: &[u8]) {
        let encoded = compress(input).expect("compression should succeed");
        assert_eq!(
            decompress(&encoded, input.len(), input.len()),
            Ok(input.to_vec()),
            "round trip failed for {} bytes",
            input.len()
        );
        assert_eq!(
            compress(input).expect("second compression should succeed"),
            encoded,
            "compression was nondeterministic for {} bytes",
            input.len()
        );
    }
}
