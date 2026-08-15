use std::error::Error as StdError;
use std::fmt;

const FLAG_BITS: u8 = 32;
const MAX_OFFSET: usize = 1 << 13;
const MIN_MATCH: usize = 3;
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN_STEPS: usize = 64;
const NO_POSITION: usize = usize::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    AllocationFailed,
    ExpectedSizeExceedsLimit { expected: usize, limit: usize },
    ExpectedSizeTooLarge { expected: usize },
    IntegerOverflow,
    InvalidMatchLength { encoded: usize },
    InvalidOffset { offset: usize, produced: usize },
    OutputExceedsExpected { attempted: usize, expected: usize },
    OutputExceedsLimit { attempted: usize, limit: usize },
    OutputSizeMismatch { actual: usize, expected: usize },
    Truncated(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocationFailed => formatter.write_str("unable to allocate output buffer"),
            Self::ExpectedSizeExceedsLimit { expected, limit } => {
                write!(
                    formatter,
                    "expected_size ({expected}) exceeds max_output_size ({limit})"
                )
            }
            Self::ExpectedSizeTooLarge { expected } => {
                write!(
                    formatter,
                    "expected_size ({expected}) is too large for an output buffer"
                )
            }
            Self::IntegerOverflow => formatter.write_str("integer overflow in compressed stream"),
            Self::InvalidMatchLength { encoded } => {
                write!(formatter, "invalid extended match length {encoded}")
            }
            Self::InvalidOffset { offset, produced } => {
                write!(
                    formatter,
                    "invalid match offset {offset} with only {produced} bytes decoded"
                )
            }
            Self::OutputExceedsExpected {
                attempted,
                expected,
            } => {
                write!(
                    formatter,
                    "decoded output would reach {attempted} bytes, exceeding expected_size {expected}"
                )
            }
            Self::OutputExceedsLimit { attempted, limit } => {
                write!(
                    formatter,
                    "decoded output would reach {attempted} bytes, exceeding max_output_size {limit}"
                )
            }
            Self::OutputSizeMismatch { actual, expected } => {
                write!(
                    formatter,
                    "decoded output is {actual} bytes, expected {expected}"
                )
            }
            Self::Truncated(component) => {
                write!(
                    formatter,
                    "truncated or malformed compressed stream while reading {component}"
                )
            }
        }
    }
}

impl StdError for CodecError {}

pub fn compress(data: &[u8]) -> Result<Vec<u8>, CodecError> {
    let flag_word_count = data
        .len()
        .checked_div(usize::from(FLAG_BITS))
        .and_then(|count| count.checked_add(1))
        .ok_or(CodecError::IntegerOverflow)?;
    let flag_bytes = flag_word_count
        .checked_mul(size_of::<u32>())
        .ok_or(CodecError::IntegerOverflow)?;
    let maximum_size = data
        .len()
        .checked_add(flag_bytes)
        .ok_or(CodecError::IntegerOverflow)?;

    let mut encoder = Encoder::new(maximum_size)?;
    let mut finder = MatchFinder::new(data.len())?;
    let mut position = 0usize;

    while position < data.len() {
        let best_match = finder.find(data, position);
        let token_end = if let Some((offset, length)) = best_match {
            encoder.write_match(offset, length)?;
            position
                .checked_add(length)
                .ok_or(CodecError::IntegerOverflow)?
        } else {
            encoder.write_literal(data[position])?;
            position.checked_add(1).ok_or(CodecError::IntegerOverflow)?
        };

        for dictionary_position in position..token_end {
            finder.insert(data, dictionary_position);
        }
        position = token_end;
    }

    encoder.finish()
}

pub fn decompress(
    data: &[u8],
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
    let mut flags = 0u32;
    let mut remaining_flags = 0u8;
    let mut pending_high_nibble = None;

    loop {
        if remaining_flags == 0 {
            flags = read_u32(data, &mut input_position, "flag word")?;
            remaining_flags = FLAG_BITS;
        }

        remaining_flags = remaining_flags
            .checked_sub(1)
            .ok_or(CodecError::IntegerOverflow)?;
        let is_match = (flags & (1u32 << remaining_flags)) != 0;

        if !is_match {
            let attempted = output
                .len()
                .checked_add(1)
                .ok_or(CodecError::IntegerOverflow)?;
            check_output_size(attempted, expected_size, max_output_size)?;
            output.push(read_u8(data, &mut input_position, "literal")?);
            continue;
        }

        // A one-bit with no payload left is the terminal marker produced by
        // padding the unused low bits of the final flag word with ones.
        if input_position == data.len() {
            if output.len() != expected_size {
                return Err(CodecError::OutputSizeMismatch {
                    actual: output.len(),
                    expected: expected_size,
                });
            }
            return Ok(output);
        }

        let match_word = read_u16(data, &mut input_position, "match word")?;
        let match_offset = usize::from(match_word >> 3)
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;
        let mut match_length = usize::from(match_word & 0b111);

        if match_length == 7 {
            let nibble = if let Some(nibble_position) = pending_high_nibble.take() {
                data.get(nibble_position)
                    .copied()
                    .ok_or(CodecError::Truncated("saved length nibble"))?
                    >> 4
            } else {
                let nibble_position = input_position;
                let byte = read_u8(data, &mut input_position, "length nibble")?;
                pending_high_nibble = Some(nibble_position);
                byte & 0x0f
            };
            match_length = usize::from(nibble);

            if match_length == 15 {
                match_length =
                    usize::from(read_u8(data, &mut input_position, "8-bit match length")?);
                if match_length == 255 {
                    let encoded_length =
                        read_u16(data, &mut input_position, "16-bit match length")?;
                    match_length = if encoded_length == 0 {
                        usize::try_from(read_u32(data, &mut input_position, "32-bit match length")?)
                            .map_err(|_| CodecError::IntegerOverflow)?
                    } else {
                        usize::from(encoded_length)
                    };
                    if match_length < 15 + 7 {
                        return Err(CodecError::InvalidMatchLength {
                            encoded: match_length,
                        });
                    }
                    match_length = match_length
                        .checked_sub(15 + 7)
                        .ok_or(CodecError::IntegerOverflow)?;
                }
                match_length = match_length
                    .checked_add(15)
                    .ok_or(CodecError::IntegerOverflow)?;
            }
            match_length = match_length
                .checked_add(7)
                .ok_or(CodecError::IntegerOverflow)?;
        }
        match_length = match_length
            .checked_add(MIN_MATCH)
            .ok_or(CodecError::IntegerOverflow)?;

        if match_offset > output.len() {
            return Err(CodecError::InvalidOffset {
                offset: match_offset,
                produced: output.len(),
            });
        }

        let attempted = output
            .len()
            .checked_add(match_length)
            .ok_or(CodecError::IntegerOverflow)?;
        check_output_size(attempted, expected_size, max_output_size)?;

        // Deliberately copy one byte at a time. The source index advances as
        // output grows, which implements overlapping LZ77 back-references.
        for _ in 0..match_length {
            let source_position = output
                .len()
                .checked_sub(match_offset)
                .ok_or(CodecError::IntegerOverflow)?;
            let byte = output[source_position];
            output.push(byte);
        }
    }
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

fn read_u8(data: &[u8], position: &mut usize, component: &'static str) -> Result<u8, CodecError> {
    let value = data
        .get(*position)
        .copied()
        .ok_or(CodecError::Truncated(component))?;
    *position = position.checked_add(1).ok_or(CodecError::IntegerOverflow)?;
    Ok(value)
}

fn read_u16(data: &[u8], position: &mut usize, component: &'static str) -> Result<u16, CodecError> {
    let end = position
        .checked_add(size_of::<u16>())
        .ok_or(CodecError::IntegerOverflow)?;
    let bytes: [u8; 2] = data
        .get(*position..end)
        .ok_or(CodecError::Truncated(component))?
        .try_into()
        .map_err(|_| CodecError::Truncated(component))?;
    *position = end;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], position: &mut usize, component: &'static str) -> Result<u32, CodecError> {
    let end = position
        .checked_add(size_of::<u32>())
        .ok_or(CodecError::IntegerOverflow)?;
    let bytes: [u8; 4] = data
        .get(*position..end)
        .ok_or(CodecError::Truncated(component))?
        .try_into()
        .map_err(|_| CodecError::Truncated(component))?;
    *position = end;
    Ok(u32::from_le_bytes(bytes))
}

struct Encoder {
    output: Vec<u8>,
    flags: u32,
    flag_count: u8,
    flag_position: usize,
    pending_high_nibble: Option<usize>,
}

impl Encoder {
    fn new(capacity: usize) -> Result<Self, CodecError> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| CodecError::AllocationFailed)?;
        output.extend_from_slice(&[0; size_of::<u32>()]);
        Ok(Self {
            output,
            flags: 0,
            flag_count: 0,
            flag_position: 0,
            pending_high_nibble: None,
        })
    }

    fn write_literal(&mut self, literal: u8) -> Result<(), CodecError> {
        self.output.push(literal);
        self.write_flag(false)
    }

    fn write_match(&mut self, offset: usize, length: usize) -> Result<(), CodecError> {
        let encoded_offset = offset
            .checked_sub(1)
            .and_then(|value| value.checked_shl(3))
            .ok_or(CodecError::IntegerOverflow)?;
        let adjusted_length = length
            .checked_sub(MIN_MATCH)
            .ok_or(CodecError::IntegerOverflow)?;

        if adjusted_length < 7 {
            let match_word = encoded_offset
                .checked_add(adjusted_length)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(CodecError::IntegerOverflow)?;
            self.output.extend_from_slice(&match_word.to_le_bytes());
        } else {
            let match_word = encoded_offset
                .checked_add(7)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or(CodecError::IntegerOverflow)?;
            self.output.extend_from_slice(&match_word.to_le_bytes());

            let nibble_length = adjusted_length
                .checked_sub(7)
                .ok_or(CodecError::IntegerOverflow)?;
            let nibble =
                u8::try_from(nibble_length.min(15)).map_err(|_| CodecError::IntegerOverflow)?;

            if let Some(nibble_position) = self.pending_high_nibble.take() {
                let slot = self
                    .output
                    .get_mut(nibble_position)
                    .ok_or(CodecError::IntegerOverflow)?;
                *slot |= nibble << 4;
            } else {
                self.pending_high_nibble = Some(self.output.len());
                self.output.push(nibble);
            }

            if nibble_length >= 15 {
                self.write_extra_length(adjusted_length, nibble_length)?;
            }
        }

        self.write_flag(true)
    }

    fn write_extra_length(
        &mut self,
        adjusted_length: usize,
        nibble_length: usize,
    ) -> Result<(), CodecError> {
        let byte_length = nibble_length
            .checked_sub(15)
            .ok_or(CodecError::IntegerOverflow)?;
        if byte_length < 255 {
            self.output
                .push(u8::try_from(byte_length).map_err(|_| CodecError::IntegerOverflow)?);
            return Ok(());
        }

        self.output.push(255);
        if adjusted_length < (1 << 16) {
            let encoded =
                u16::try_from(adjusted_length).map_err(|_| CodecError::IntegerOverflow)?;
            self.output.extend_from_slice(&encoded.to_le_bytes());
        } else {
            let encoded =
                u32::try_from(adjusted_length).map_err(|_| CodecError::IntegerOverflow)?;
            self.output.extend_from_slice(&0u16.to_le_bytes());
            self.output.extend_from_slice(&encoded.to_le_bytes());
        }
        Ok(())
    }

    fn write_flag(&mut self, is_match: bool) -> Result<(), CodecError> {
        self.flags = self
            .flags
            .checked_shl(1)
            .ok_or(CodecError::IntegerOverflow)?
            | u32::from(is_match);
        self.flag_count = self
            .flag_count
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;

        if self.flag_count == FLAG_BITS {
            self.patch_flags()?;
            self.flags = 0;
            self.flag_count = 0;
            self.flag_position = self.output.len();
            self.output.extend_from_slice(&[0; size_of::<u32>()]);
        }
        Ok(())
    }

    fn patch_flags(&mut self) -> Result<(), CodecError> {
        let end = self
            .flag_position
            .checked_add(size_of::<u32>())
            .ok_or(CodecError::IntegerOverflow)?;
        let destination = self
            .output
            .get_mut(self.flag_position..end)
            .ok_or(CodecError::IntegerOverflow)?;
        destination.copy_from_slice(&self.flags.to_le_bytes());
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, CodecError> {
        self.flags = if self.flag_count == 0 {
            u32::MAX
        } else {
            let padding = u32::from(
                FLAG_BITS
                    .checked_sub(self.flag_count)
                    .ok_or(CodecError::IntegerOverflow)?,
            );
            let padding_bits = (1u32 << padding)
                .checked_sub(1)
                .ok_or(CodecError::IntegerOverflow)?;
            self.flags
                .checked_shl(padding)
                .ok_or(CodecError::IntegerOverflow)?
                | padding_bits
        };
        self.patch_flags()?;
        Ok(self.output)
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

    fn find(&self, data: &[u8], position: usize) -> Option<(usize, usize)> {
        if data.len().checked_sub(position)? < MIN_MATCH {
            return None;
        }

        let maximum_length = data.len().checked_sub(position)?.min(u32::MAX as usize);
        let mut candidate = self.heads[hash_at(data, position)?];
        let mut best = None;
        let mut steps = 0usize;

        while candidate != NO_POSITION && steps < MAX_CHAIN_STEPS {
            let offset = position.checked_sub(candidate)?;
            if offset > MAX_OFFSET {
                break;
            }

            if data.get(candidate..candidate.checked_add(MIN_MATCH)?)
                == data.get(position..position.checked_add(MIN_MATCH)?)
            {
                let mut length = MIN_MATCH;
                while length < maximum_length
                    && data.get(candidate.checked_add(length)?)
                        == data.get(position.checked_add(length)?)
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

    fn insert(&mut self, data: &[u8], position: usize) {
        let Some(hash) = hash_at(data, position) else {
            return;
        };
        self.previous[position] = self.heads[hash];
        self.heads[hash] = position;
    }
}

fn hash_at(data: &[u8], position: usize) -> Option<usize> {
    let bytes = data.get(position..position.checked_add(MIN_MATCH)?)?;
    let value = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    let mixed = value.wrapping_mul(2_654_435_761);
    Some((mixed >> (32 - HASH_BITS)) as usize)
}

#[cfg(test)]
mod tests {
    use super::{CodecError, compress, decompress};

    #[test]
    fn empty_stream_is_a_terminal_flag_word() {
        assert_eq!(compress(b""), Ok(vec![0xff; 4]));
        assert_eq!(decompress(&[0xff; 4], 0, 0), Ok(Vec::new()));
    }

    #[test]
    fn overlapping_match_copies_from_growing_output() {
        let encoded = [0xff, 0xff, 0xff, 0x7f, b'a', 0x02, 0x00];
        assert_eq!(decompress(&encoded, 6, 6), Ok(b"aaaaaa".to_vec()));
    }

    #[test]
    fn match_cannot_refer_before_output() {
        let encoded = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00];
        assert!(matches!(
            decompress(&encoded, 3, 3),
            Err(CodecError::InvalidOffset {
                offset: 1,
                produced: 0
            })
        ));
    }
}
