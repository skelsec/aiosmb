//! Safe Rust implementation of the MS-XCA XPRESS LZ77+Huffman format.
//!
//! XPRESS Huffman operates on independent 64 KiB blocks.  Every block starts
//! with 512 canonical Huffman code lengths packed into 256 bytes, followed by
//! the format's interleaved, big-endian-in-16-bit-units bitstream.

use crate::codec::CodecError;

const BLOCK_SIZE: usize = 65_536;
const SYMBOL_COUNT: usize = 512;
const LITERAL_COUNT: usize = 256;
const END_OF_DATA_SYMBOL: usize = 256;
const LENGTH_TABLE_SIZE: usize = SYMBOL_COUNT / 2;
const MAX_CODE_LENGTH: usize = 15;
const DECODE_TABLE_BITS: usize = MAX_CODE_LENGTH;
const DECODE_TABLE_SIZE: usize = 1 << DECODE_TABLE_BITS;
const MIN_MATCH: usize = 3;
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN_STEPS: usize = 64;
const NO_POSITION: usize = usize::MAX;

/// Compresses `input` using the MS-XCA XPRESS LZ77+Huffman stream format.
///
/// Match selection, Huffman tie-breaking, and canonical code assignment are
/// deterministic, so identical input always produces identical output.
pub fn compress(input: &[u8]) -> Result<Vec<u8>, CodecError> {
    let block_count = if input.is_empty() {
        1
    } else {
        input
            .len()
            .checked_sub(1)
            .and_then(|value| value.checked_div(BLOCK_SIZE))
            .and_then(|value| value.checked_add(1))
            .ok_or(CodecError::IntegerOverflow)?
    };
    let maximum_size = input
        .len()
        .checked_mul(2)
        .and_then(|value| {
            block_count
                .checked_mul(LENGTH_TABLE_SIZE + 4)
                .and_then(|overhead| value.checked_add(overhead))
        })
        .ok_or(CodecError::IntegerOverflow)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(maximum_size)
        .map_err(|_| CodecError::AllocationFailed)?;

    if input.is_empty() {
        encode_block(input, true, &mut output)?;
        return Ok(output);
    }

    for (index, block) in input.chunks(BLOCK_SIZE).enumerate() {
        encode_block(block, index + 1 == block_count, &mut output)?;
    }
    Ok(output)
}

/// Decompresses an MS-XCA XPRESS LZ77+Huffman stream with strict output bounds.
///
/// `expected_size` is the exact required result size.  No literal or match may
/// grow the output beyond either `expected_size` or `max_output_size`.
pub fn decompress(
    input: &[u8],
    expected_size: usize,
    max_output_size: usize,
) -> Result<Vec<u8>, CodecError> {
    validate_expected_size(expected_size, max_output_size)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(expected_size)
        .map_err(|_| CodecError::AllocationFailed)?;

    let mut input_position = 0usize;
    loop {
        let table_end = input_position
            .checked_add(LENGTH_TABLE_SIZE)
            .ok_or(CodecError::IntegerOverflow)?;
        let packed_lengths = input
            .get(input_position..table_end)
            .ok_or(CodecError::Truncated("Huffman code-length table"))?;
        let lengths = unpack_code_lengths(packed_lengths);
        let decode_table = build_decode_table(&lengths)?;
        let mut reader = BitReader::new(input, table_end)?;

        let block_start = output.len();
        let block_end = block_start
            .checked_add(BLOCK_SIZE)
            .ok_or(CodecError::IntegerOverflow)?
            .min(expected_size);

        while output.len() < block_end {
            let symbol = reader.read_symbol(&decode_table, &lengths)?;
            if symbol < LITERAL_COUNT {
                let attempted = output
                    .len()
                    .checked_add(1)
                    .ok_or(CodecError::IntegerOverflow)?;
                check_output_size(attempted, expected_size, max_output_size)?;
                output.push(u8::try_from(symbol).map_err(|_| CodecError::IntegerOverflow)?);
                continue;
            }

            let match_symbol = symbol
                .checked_sub(LITERAL_COUNT)
                .ok_or(CodecError::IntegerOverflow)?;
            let length_header = match_symbol & 0x0f;
            let offset_bit_count = (match_symbol >> 4) & 0x0f;
            let match_length = read_match_length(&mut reader, length_header)?;
            let offset_low_bits = usize::try_from(reader.read_bits(offset_bit_count)?)
                .map_err(|_| CodecError::IntegerOverflow)?;
            let match_offset = (1usize << offset_bit_count)
                .checked_add(offset_low_bits)
                .ok_or(CodecError::IntegerOverflow)?;
            let produced_in_block = output
                .len()
                .checked_sub(block_start)
                .ok_or(CodecError::IntegerOverflow)?;

            if match_offset > produced_in_block {
                return Err(CodecError::InvalidOffset {
                    offset: match_offset,
                    produced: produced_in_block,
                });
            }

            let attempted = output
                .len()
                .checked_add(match_length)
                .ok_or(CodecError::IntegerOverflow)?;
            check_output_size(attempted, expected_size, max_output_size)?;

            // The source position is recomputed as output grows.  This is
            // required for overlapping references such as (offset=1, len=5).
            for _ in 0..match_length {
                let source = output
                    .len()
                    .checked_sub(match_offset)
                    .ok_or(CodecError::IntegerOverflow)?;
                let byte = output[source];
                output.push(byte);
            }
        }

        if output.len() == expected_size {
            let symbol = reader.read_symbol(&decode_table, &lengths)?;
            if symbol != END_OF_DATA_SYMBOL {
                return Err(malformed("end-of-data Huffman symbol"));
            }
            if reader.position() != input.len() {
                return Err(malformed("trailing XPRESS Huffman data"));
            }
            return Ok(output);
        }

        input_position = reader.position();
        if input_position >= input.len() {
            return Err(CodecError::OutputSizeMismatch {
                actual: output.len(),
                expected: expected_size,
            });
        }
    }
}

fn validate_expected_size(expected_size: usize, max_output_size: usize) -> Result<(), CodecError> {
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

fn malformed(component: &'static str) -> CodecError {
    // CodecError intentionally has no generic malformed-stream variant.  Keep
    // all format failures in the existing public error type without changing
    // another module.
    CodecError::Truncated(component)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    Literal(u8),
    Match { offset: usize, length: usize },
}

fn encode_block(input: &[u8], is_final: bool, output: &mut Vec<u8>) -> Result<(), CodecError> {
    let (tokens, mut frequencies) = tokenize(input)?;
    if is_final {
        frequencies[END_OF_DATA_SYMBOL] = frequencies[END_OF_DATA_SYMBOL]
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;
    }

    let lengths = build_huffman_lengths(&frequencies)?;
    let codes = build_canonical_codes(&lengths)?;

    for pair in lengths.chunks_exact(2) {
        output.push(pair[0] | (pair[1] << 4));
    }

    let bit_capacity = input
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(16))
        .ok_or(CodecError::IntegerOverflow)?;
    let mut writer = BitWriter::new(bit_capacity)?;

    for token in tokens {
        match token {
            Token::Literal(byte) => {
                write_symbol(&mut writer, usize::from(byte), &codes, &lengths)?;
            }
            Token::Match { offset, length } => {
                let adjusted_length = length
                    .checked_sub(MIN_MATCH)
                    .ok_or(CodecError::IntegerOverflow)?;
                let offset_bit_count = high_bit(offset)?;
                let length_header = adjusted_length.min(15);
                let symbol = LITERAL_COUNT
                    .checked_add(offset_bit_count << 4)
                    .and_then(|value| value.checked_add(length_header))
                    .ok_or(CodecError::IntegerOverflow)?;

                write_symbol(&mut writer, symbol, &codes, &lengths)?;
                write_extra_length(&mut writer, adjusted_length)?;
                let offset_base = 1usize << offset_bit_count;
                let offset_low_bits = offset
                    .checked_sub(offset_base)
                    .ok_or(CodecError::IntegerOverflow)?;
                writer.write_bits(
                    u32::try_from(offset_low_bits).map_err(|_| CodecError::IntegerOverflow)?,
                    offset_bit_count,
                )?;
            }
        }
    }

    if is_final {
        write_symbol(&mut writer, END_OF_DATA_SYMBOL, &codes, &lengths)?;
    }
    output.extend_from_slice(&writer.finish()?);
    Ok(())
}

fn write_symbol(
    writer: &mut BitWriter,
    symbol: usize,
    codes: &[u16; SYMBOL_COUNT],
    lengths: &[u8; SYMBOL_COUNT],
) -> Result<(), CodecError> {
    let length = usize::from(lengths[symbol]);
    if length == 0 {
        return Err(malformed("missing encoder Huffman symbol"));
    }
    writer.write_bits(u32::from(codes[symbol]), length)
}

fn write_extra_length(writer: &mut BitWriter, adjusted_length: usize) -> Result<(), CodecError> {
    if adjusted_length < 15 {
        return Ok(());
    }

    let extra = adjusted_length
        .checked_sub(15)
        .ok_or(CodecError::IntegerOverflow)?;
    if extra < 255 {
        writer.write_byte(u8::try_from(extra).map_err(|_| CodecError::IntegerOverflow)?);
        return Ok(());
    }

    writer.write_byte(255);
    if adjusted_length < (1 << 16) {
        writer.write_u16(u16::try_from(adjusted_length).map_err(|_| CodecError::IntegerOverflow)?);
    } else {
        writer.write_u16(0);
        writer.write_u32(u32::try_from(adjusted_length).map_err(|_| CodecError::IntegerOverflow)?);
    }
    Ok(())
}

fn read_match_length(
    reader: &mut BitReader<'_>,
    length_header: usize,
) -> Result<usize, CodecError> {
    let adjusted_length = if length_header < 15 {
        length_header
    } else {
        let extra = usize::from(reader.read_byte("8-bit match length")?);
        if extra < 255 {
            extra.checked_add(15).ok_or(CodecError::IntegerOverflow)?
        } else {
            let encoded = reader.read_u16("16-bit match length")?;
            let encoded = if encoded == 0 {
                usize::try_from(reader.read_u32("32-bit match length")?)
                    .map_err(|_| CodecError::IntegerOverflow)?
            } else {
                usize::from(encoded)
            };
            if encoded < 15 {
                return Err(CodecError::InvalidMatchLength { encoded });
            }
            encoded
        }
    };

    adjusted_length
        .checked_add(MIN_MATCH)
        .ok_or(CodecError::IntegerOverflow)
}

fn high_bit(value: usize) -> Result<usize, CodecError> {
    if value == 0 {
        return Err(CodecError::InvalidOffset {
            offset: 0,
            produced: 0,
        });
    }
    let bit = usize::BITS
        .checked_sub(1)
        .and_then(|top| top.checked_sub(value.leading_zeros()))
        .ok_or(CodecError::IntegerOverflow)?;
    let bit = usize::try_from(bit).map_err(|_| CodecError::IntegerOverflow)?;
    if bit > 15 {
        return Err(CodecError::IntegerOverflow);
    }
    Ok(bit)
}

fn tokenize(input: &[u8]) -> Result<(Vec<Token>, [u32; SYMBOL_COUNT]), CodecError> {
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(input.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut frequencies = [0u32; SYMBOL_COUNT];
    let mut finder = MatchFinder::new(input.len())?;
    let mut position = 0usize;

    while position < input.len() {
        let (token, token_end) = if let Some((offset, length)) = finder.find(input, position) {
            let adjusted_length = length
                .checked_sub(MIN_MATCH)
                .ok_or(CodecError::IntegerOverflow)?;
            let symbol = LITERAL_COUNT
                .checked_add(high_bit(offset)? << 4)
                .and_then(|value| value.checked_add(adjusted_length.min(15)))
                .ok_or(CodecError::IntegerOverflow)?;
            frequencies[symbol] = frequencies[symbol]
                .checked_add(1)
                .ok_or(CodecError::IntegerOverflow)?;
            (
                Token::Match { offset, length },
                position
                    .checked_add(length)
                    .ok_or(CodecError::IntegerOverflow)?,
            )
        } else {
            let byte = input[position];
            frequencies[usize::from(byte)] = frequencies[usize::from(byte)]
                .checked_add(1)
                .ok_or(CodecError::IntegerOverflow)?;
            (
                Token::Literal(byte),
                position.checked_add(1).ok_or(CodecError::IntegerOverflow)?,
            )
        };

        tokens.push(token);
        for dictionary_position in position..token_end {
            finder.insert(input, dictionary_position);
        }
        position = token_end;
    }

    Ok((tokens, frequencies))
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

    fn find(&self, input: &[u8], position: usize) -> Option<(usize, usize)> {
        if input.len().checked_sub(position)? < MIN_MATCH {
            return None;
        }

        let maximum_length = input.len().checked_sub(position)?;
        let mut candidate = self.heads[hash_at(input, position)?];
        let mut best = None;
        let mut steps = 0usize;

        while candidate != NO_POSITION && steps < MAX_CHAIN_STEPS {
            let offset = position.checked_sub(candidate)?;
            if offset >= BLOCK_SIZE {
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
    let value = (u32::from(bytes[0]) << 16) | (u32::from(bytes[1]) << 8) | u32::from(bytes[2]);
    Some((value.wrapping_mul(2_654_435_761) >> (32 - HASH_BITS)) as usize)
}

#[derive(Clone, Copy)]
struct PackageNode {
    weight: u64,
    symbol: Option<usize>,
    children: Option<(usize, usize)>,
}

fn build_huffman_lengths(
    frequencies: &[u32; SYMBOL_COUNT],
) -> Result<[u8; SYMBOL_COUNT], CodecError> {
    let mut weights = *frequencies;
    let mut used = Vec::new();
    used.try_reserve_exact(SYMBOL_COUNT)
        .map_err(|_| CodecError::AllocationFailed)?;
    for (symbol, &frequency) in weights.iter().enumerate() {
        if frequency != 0 {
            used.push(symbol);
        }
    }

    if used.is_empty() {
        return Err(malformed("empty Huffman alphabet"));
    }
    if used.len() == 1 {
        let dummy = if used[0] == 0 { 1 } else { 0 };
        weights[dummy] = 1;
        used.push(dummy);
    }
    used.sort_by_key(|&symbol| (weights[symbol], symbol));

    // Binary package-merge computes an optimal length-limited code.  Reusing
    // the leaf nodes at each level models one coin of every denomination for
    // every symbol; package nodes always refer to earlier nodes, forming a DAG.
    let selection_count = used
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_sub(1))
        .and_then(|value| value.checked_sub(1))
        .ok_or(CodecError::IntegerOverflow)?;
    let maximum_packages_per_level = selection_count / 2;
    let node_capacity = (MAX_CODE_LENGTH - 1)
        .checked_mul(maximum_packages_per_level)
        .and_then(|value| value.checked_add(used.len()))
        .ok_or(CodecError::IntegerOverflow)?;
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(node_capacity)
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(used.len())
        .map_err(|_| CodecError::AllocationFailed)?;

    for &symbol in &used {
        nodes.push(PackageNode {
            weight: u64::from(weights[symbol]),
            symbol: Some(symbol),
            children: None,
        });
        leaves.push(nodes.len() - 1);
    }

    let mut current = leaves.clone();
    for _ in 1..MAX_CODE_LENGTH {
        let mut packages = Vec::new();
        packages
            .try_reserve_exact(current.len() / 2)
            .map_err(|_| CodecError::AllocationFailed)?;
        for pair in current.chunks_exact(2) {
            let left = pair[0];
            let right = pair[1];
            let weight = nodes[left]
                .weight
                .checked_add(nodes[right].weight)
                .ok_or(CodecError::IntegerOverflow)?;
            nodes.push(PackageNode {
                weight,
                symbol: None,
                children: Some((left, right)),
            });
            packages.push(nodes.len() - 1);
        }

        let next_capacity = leaves
            .len()
            .checked_add(packages.len())
            .ok_or(CodecError::IntegerOverflow)?
            .min(selection_count);
        let mut next = Vec::new();
        next.try_reserve_exact(next_capacity)
            .map_err(|_| CodecError::AllocationFailed)?;
        next.extend_from_slice(&leaves);
        next.extend_from_slice(&packages);
        next.sort_by_key(|&index| (nodes[index].weight, index));
        next.truncate(selection_count);
        current = next;
    }
    if current.len() < selection_count {
        return Err(malformed("length-limited Huffman tree"));
    }

    let mut uses = Vec::new();
    uses.try_reserve_exact(nodes.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    uses.resize(nodes.len(), 0u32);
    for &node_index in current.iter().take(selection_count) {
        uses[node_index] = uses[node_index]
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;
    }

    let mut lengths = [0u8; SYMBOL_COUNT];
    for node_index in (0..nodes.len()).rev() {
        let count = uses[node_index];
        if count == 0 {
            continue;
        }
        let node = nodes[node_index];
        if let Some(symbol) = node.symbol {
            if count == 0 || count > MAX_CODE_LENGTH as u32 {
                return Err(malformed("length-limited Huffman tree"));
            }
            lengths[symbol] = u8::try_from(count).map_err(|_| CodecError::IntegerOverflow)?;
        } else if let Some((left, right)) = node.children {
            uses[left] = uses[left]
                .checked_add(count)
                .ok_or(CodecError::IntegerOverflow)?;
            uses[right] = uses[right]
                .checked_add(count)
                .ok_or(CodecError::IntegerOverflow)?;
        } else {
            return Err(malformed("length-limited Huffman tree"));
        }
    }
    if used.iter().any(|&symbol| lengths[symbol] == 0) {
        return Err(malformed("encoder Huffman lengths"));
    }

    // Validate the result before it reaches the output stream.
    let _ = build_canonical_codes(&lengths)?;
    Ok(lengths)
}

fn build_canonical_codes(lengths: &[u8; SYMBOL_COUNT]) -> Result<[u16; SYMBOL_COUNT], CodecError> {
    let mut counts = [0u32; MAX_CODE_LENGTH + 1];
    for &length in lengths {
        let length = usize::from(length);
        if length > MAX_CODE_LENGTH {
            return Err(malformed("Huffman code length"));
        }
        if length != 0 {
            counts[length] = counts[length]
                .checked_add(1)
                .ok_or(CodecError::IntegerOverflow)?;
        }
    }

    let mut next_code = [0u32; MAX_CODE_LENGTH + 1];
    let mut code = 0u32;
    for length in 1..=MAX_CODE_LENGTH {
        code = code
            .checked_add(counts[length - 1])
            .and_then(|value| value.checked_shl(1))
            .ok_or(CodecError::IntegerOverflow)?;
        if code > (1u32 << length) {
            return Err(malformed("oversubscribed Huffman code-length table"));
        }
        next_code[length] = code;
    }
    if code
        .checked_add(counts[MAX_CODE_LENGTH])
        .ok_or(CodecError::IntegerOverflow)?
        != (1u32 << MAX_CODE_LENGTH)
    {
        return Err(malformed("incomplete Huffman code-length table"));
    }

    let mut codes = [0u16; SYMBOL_COUNT];
    for (symbol, &length) in lengths.iter().enumerate() {
        let length = usize::from(length);
        if length == 0 {
            continue;
        }
        codes[symbol] =
            u16::try_from(next_code[length]).map_err(|_| CodecError::IntegerOverflow)?;
        next_code[length] = next_code[length]
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;
    }
    Ok(codes)
}

fn unpack_code_lengths(packed: &[u8]) -> [u8; SYMBOL_COUNT] {
    let mut lengths = [0u8; SYMBOL_COUNT];
    for (index, &byte) in packed.iter().enumerate() {
        lengths[index * 2] = byte & 0x0f;
        lengths[index * 2 + 1] = byte >> 4;
    }
    lengths
}

fn build_decode_table(lengths: &[u8; SYMBOL_COUNT]) -> Result<Vec<u16>, CodecError> {
    // Canonical validation catches both over- and under-subscribed trees.
    let _ = build_canonical_codes(lengths)?;

    let mut table = Vec::new();
    table
        .try_reserve_exact(DECODE_TABLE_SIZE)
        .map_err(|_| CodecError::AllocationFailed)?;
    for length in 1..=MAX_CODE_LENGTH {
        let repeat = 1usize << (MAX_CODE_LENGTH - length);
        for (symbol, &symbol_length) in lengths.iter().enumerate() {
            if usize::from(symbol_length) != length {
                continue;
            }
            let attempted = table
                .len()
                .checked_add(repeat)
                .ok_or(CodecError::IntegerOverflow)?;
            if attempted > DECODE_TABLE_SIZE {
                return Err(malformed("oversubscribed Huffman code-length table"));
            }
            let symbol = u16::try_from(symbol).map_err(|_| CodecError::IntegerOverflow)?;
            table.resize(attempted, symbol);
        }
    }
    if table.len() != DECODE_TABLE_SIZE {
        return Err(malformed("incomplete Huffman code-length table"));
    }
    Ok(table)
}

struct BitWriter {
    bytes: Vec<u8>,
    pending: u32,
    pending_bits: usize,
    next_bits: usize,
    next_bits_2: usize,
    next_byte: usize,
}

impl BitWriter {
    fn new(capacity: usize) -> Result<Self, CodecError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity.max(4))
            .map_err(|_| CodecError::AllocationFailed)?;
        bytes.resize(4, 0);
        Ok(Self {
            bytes,
            pending: 0,
            pending_bits: 0,
            next_bits: 0,
            next_bits_2: 2,
            next_byte: 4,
        })
    }

    fn write_bits(&mut self, bits: u32, bit_count: usize) -> Result<(), CodecError> {
        if bit_count > 16 || (bit_count < 32 && bits >= (1u32 << bit_count)) {
            return Err(CodecError::IntegerOverflow);
        }
        if bit_count == 0 {
            return Ok(());
        }

        let combined_bits = self
            .pending_bits
            .checked_add(bit_count)
            .ok_or(CodecError::IntegerOverflow)?;
        let combined = self
            .pending
            .checked_shl(u32::try_from(bit_count).map_err(|_| CodecError::IntegerOverflow)?)
            .ok_or(CodecError::IntegerOverflow)?
            | bits;

        if combined_bits > 16 {
            let remaining = combined_bits
                .checked_sub(16)
                .ok_or(CodecError::IntegerOverflow)?;
            let word =
                u16::try_from(combined >> remaining).map_err(|_| CodecError::IntegerOverflow)?;
            self.patch_word(self.next_bits, word)?;
            self.next_bits = self.next_bits_2;
            self.next_bits_2 = self.next_byte;
            self.bytes.extend_from_slice(&[0, 0]);
            self.next_byte = self
                .next_byte
                .checked_add(2)
                .ok_or(CodecError::IntegerOverflow)?;
            self.pending_bits = remaining;
            self.pending = if remaining == 0 {
                0
            } else {
                combined & ((1u32 << remaining) - 1)
            };
        } else {
            self.pending = combined;
            self.pending_bits = combined_bits;
        }
        Ok(())
    }

    fn write_byte(&mut self, byte: u8) {
        self.bytes.push(byte);
        self.next_byte += 1;
    }

    fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.next_byte += 2;
    }

    fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self.next_byte += 4;
    }

    fn patch_word(&mut self, position: usize, word: u16) -> Result<(), CodecError> {
        let end = position.checked_add(2).ok_or(CodecError::IntegerOverflow)?;
        let destination = self
            .bytes
            .get_mut(position..end)
            .ok_or(CodecError::IntegerOverflow)?;
        destination.copy_from_slice(&word.to_le_bytes());
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, CodecError> {
        let shift = 16usize
            .checked_sub(self.pending_bits)
            .ok_or(CodecError::IntegerOverflow)?;
        let final_word =
            u16::try_from(self.pending << shift).map_err(|_| CodecError::IntegerOverflow)?;
        self.patch_word(self.next_bits, final_word)?;
        self.patch_word(self.next_bits_2, 0)?;
        if self.bytes.len() != self.next_byte {
            return Err(CodecError::IntegerOverflow);
        }
        Ok(self.bytes)
    }
}

struct BitReader<'a> {
    input: &'a [u8],
    next_bits: u32,
    extra_bit_count: i32,
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8], position: usize) -> Result<Self, CodecError> {
        let first = read_u16_at(input, position, "initial Huffman bit word")?;
        let second_position = position.checked_add(2).ok_or(CodecError::IntegerOverflow)?;
        let second = read_u16_at(input, second_position, "initial Huffman bit word")?;
        let position = second_position
            .checked_add(2)
            .ok_or(CodecError::IntegerOverflow)?;
        Ok(Self {
            input,
            next_bits: (u32::from(first) << 16) | u32::from(second),
            extra_bit_count: 16,
            position,
        })
    }

    fn position(&self) -> usize {
        self.position
    }

    fn read_symbol(
        &mut self,
        table: &[u16],
        lengths: &[u8; SYMBOL_COUNT],
    ) -> Result<usize, CodecError> {
        let index = usize::try_from(self.next_bits >> (32 - DECODE_TABLE_BITS))
            .map_err(|_| CodecError::IntegerOverflow)?;
        let symbol = usize::from(
            *table
                .get(index)
                .ok_or_else(|| malformed("Huffman decode table lookup"))?,
        );
        let length = usize::from(lengths[symbol]);
        if length == 0 {
            return Err(malformed("zero-length Huffman symbol"));
        }
        self.consume_bits(length)?;
        Ok(symbol)
    }

    fn read_bits(&mut self, bit_count: usize) -> Result<u32, CodecError> {
        if bit_count > 15 {
            return Err(malformed("match offset bit count"));
        }
        if bit_count == 0 {
            return Ok(0);
        }
        let bits = self.next_bits >> (32 - bit_count);
        self.consume_bits(bit_count)?;
        Ok(bits)
    }

    fn consume_bits(&mut self, bit_count: usize) -> Result<(), CodecError> {
        self.next_bits <<= bit_count;
        self.extra_bit_count = self
            .extra_bit_count
            .checked_sub(i32::try_from(bit_count).map_err(|_| CodecError::IntegerOverflow)?)
            .ok_or(CodecError::IntegerOverflow)?;
        if self.extra_bit_count < 0 {
            let word = read_u16_at(self.input, self.position, "Huffman bit word")?;
            let shift =
                u32::try_from(-self.extra_bit_count).map_err(|_| CodecError::IntegerOverflow)?;
            self.next_bits |= u32::from(word) << shift;
            self.extra_bit_count = self
                .extra_bit_count
                .checked_add(16)
                .ok_or(CodecError::IntegerOverflow)?;
            self.position = self
                .position
                .checked_add(2)
                .ok_or(CodecError::IntegerOverflow)?;
        }
        Ok(())
    }

    fn read_byte(&mut self, component: &'static str) -> Result<u8, CodecError> {
        let byte = self
            .input
            .get(self.position)
            .copied()
            .ok_or(CodecError::Truncated(component))?;
        self.position = self
            .position
            .checked_add(1)
            .ok_or(CodecError::IntegerOverflow)?;
        Ok(byte)
    }

    fn read_u16(&mut self, component: &'static str) -> Result<u16, CodecError> {
        let value = read_u16_at(self.input, self.position, component)?;
        self.position = self
            .position
            .checked_add(2)
            .ok_or(CodecError::IntegerOverflow)?;
        Ok(value)
    }

    fn read_u32(&mut self, component: &'static str) -> Result<u32, CodecError> {
        let end = self
            .position
            .checked_add(4)
            .ok_or(CodecError::IntegerOverflow)?;
        let bytes: [u8; 4] = self
            .input
            .get(self.position..end)
            .ok_or(CodecError::Truncated(component))?
            .try_into()
            .map_err(|_| CodecError::Truncated(component))?;
        self.position = end;
        Ok(u32::from_le_bytes(bytes))
    }
}

fn read_u16_at(input: &[u8], position: usize, component: &'static str) -> Result<u16, CodecError> {
    let end = position.checked_add(2).ok_or(CodecError::IntegerOverflow)?;
    let bytes: [u8; 2] = input
        .get(position..end)
        .ok_or(CodecError::Truncated(component))?
        .try_into()
        .map_err(|_| CodecError::Truncated(component))?;
    Ok(u16::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        BLOCK_SIZE, CodecError, MAX_CODE_LENGTH, build_huffman_lengths, compress, decompress,
    };

    fn spec_stream(lengths: &[(usize, u8)], body: &[u8]) -> Vec<u8> {
        let mut encoded = vec![0u8; 256];
        for &(symbol, length) in lengths {
            let slot = &mut encoded[symbol / 2];
            if symbol & 1 == 0 {
                *slot |= length;
            } else {
                *slot |= length << 4;
            }
        }
        encoded.extend_from_slice(body);
        encoded
    }

    fn deterministic_bytes(length: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9u32;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect()
    }

    #[test]
    fn ms_xca_single_literal_vector() {
        // Canonical codes: 'A' = 0, EOF(256) = 1.  The two bits "01"
        // occupy the high end of the first little-endian 16-bit coding unit.
        let expected = spec_stream(&[(b'A' as usize, 1), (256, 1)], &[0x00, 0x40, 0, 0]);
        assert_eq!(compress(b"A"), Ok(expected.clone()));
        assert_eq!(decompress(&expected, 1, 1), Ok(b"A".to_vec()));
    }

    #[test]
    fn ms_xca_overlap_vector() {
        // Codes sorted by (length, symbol): 'a'=0, EOF=10, match(2,0)=11.
        // Tokens are literal 'a', (length=5, offset=1), EOF => 0 11 10.
        let encoded = spec_stream(
            &[(b'a' as usize, 1), (256, 2), (258, 2)],
            &[0x00, 0x70, 0, 0],
        );
        assert_eq!(decompress(&encoded, 6, 6), Ok(b"aaaaaa".to_vec()));
    }

    #[test]
    fn ms_xca_offset_bits_vector() {
        // a=00, b=01, c=10, EOF=110, match(length=3, highbit=1)=111.
        // The offset 3 contributes its low bit 1: 00 01 10 111 1 110.
        let encoded = spec_stream(
            &[
                (b'a' as usize, 2),
                (b'b' as usize, 2),
                (b'c' as usize, 2),
                (256, 3),
                (272, 3),
            ],
            &[0xf0, 0x1b, 0, 0],
        );
        assert_eq!(decompress(&encoded, 6, 6), Ok(b"abcabc".to_vec()));
    }

    #[test]
    fn ms_xca_interleaved_extended_length_vector() {
        // a=0, EOF=10, long offset-1 match=11.  Adjusted length 270 is
        // represented by 0xff followed by little-endian 0x010e after the two
        // initially prefetched coding units.
        let encoded = spec_stream(
            &[(b'a' as usize, 1), (256, 2), (271, 2)],
            &[0x00, 0x70, 0, 0, 0xff, 0x0e, 0x01],
        );
        assert_eq!(decompress(&encoded, 274, 274), Ok(vec![b'a'; 274]));
    }

    #[test]
    fn empty_round_trip_has_complete_tree_and_eof() {
        let encoded = compress(b"").unwrap();
        assert_eq!(encoded.len(), 260);
        assert_eq!(decompress(&encoded, 0, 0), Ok(Vec::new()));
    }

    #[test]
    fn round_trips_literals_matches_and_extended_lengths() {
        let cases = [
            Vec::new(),
            b"hello XPRESS Huffman".to_vec(),
            vec![b'a'; 17],
            vec![b'b'; 18],
            vec![b'c'; 272],
            vec![b'd'; 273],
            vec![b'e'; 4096],
            deterministic_bytes(8192),
        ];
        for original in cases {
            let encoded = compress(&original).unwrap();
            assert_eq!(
                decompress(&encoded, original.len(), original.len()),
                Ok(original)
            );
        }
    }

    #[test]
    fn round_trips_64k_block_boundaries() {
        for length in [
            BLOCK_SIZE - 1,
            BLOCK_SIZE,
            BLOCK_SIZE + 1,
            BLOCK_SIZE * 2 + 17,
        ] {
            let original = deterministic_bytes(length);
            let encoded = compress(&original).unwrap();
            assert_eq!(
                decompress(&encoded, original.len(), original.len()),
                Ok(original)
            );
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let original = deterministic_bytes(BLOCK_SIZE + 1234);
        let first = compress(&original).unwrap();
        let second = compress(&original).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn huffman_builder_limits_deep_trees_to_15_bits() {
        let mut frequencies = [0u32; 512];
        let (mut previous, mut current) = (1u32, 1u32);
        for frequency in frequencies.iter_mut().take(22) {
            *frequency = previous;
            (previous, current) = (current, previous + current);
        }

        let lengths = build_huffman_lengths(&frequencies).unwrap();
        assert!(
            lengths
                .iter()
                .all(|&length| usize::from(length) <= MAX_CODE_LENGTH)
        );
        assert_eq!(lengths.iter().filter(|&&length| length != 0).count(), 22);
        let kraft_sum: usize = lengths
            .iter()
            .filter(|&&length| length != 0)
            .map(|&length| 1usize << (MAX_CODE_LENGTH - usize::from(length)))
            .sum();
        assert_eq!(kraft_sum, 1 << MAX_CODE_LENGTH);
    }

    #[test]
    fn rejects_truncated_table_and_bit_window() {
        assert!(matches!(
            decompress(&[0; 255], 1, 1),
            Err(CodecError::Truncated("Huffman code-length table"))
        ));

        let encoded = spec_stream(&[(b'A' as usize, 1), (256, 1)], &[0, 0, 0]);
        assert!(matches!(
            decompress(&encoded, 1, 1),
            Err(CodecError::Truncated("initial Huffman bit word"))
        ));
    }

    #[test]
    fn rejects_incomplete_and_oversubscribed_trees() {
        let incomplete = spec_stream(&[(b'A' as usize, 1)], &[0; 4]);
        assert!(decompress(&incomplete, 1, 1).is_err());

        let oversubscribed =
            spec_stream(&[(b'A' as usize, 1), (b'B' as usize, 1), (256, 1)], &[0; 4]);
        assert!(decompress(&oversubscribed, 1, 1).is_err());
    }

    #[test]
    fn rejects_match_before_block_output() {
        // EOF=0 and match symbol 257=1; the first bit selects the match.
        let encoded = spec_stream(&[(256, 1), (257, 1)], &[0x00, 0x80, 0, 0]);
        assert!(matches!(
            decompress(&encoded, 4, 4),
            Err(CodecError::InvalidOffset {
                offset: 1,
                produced: 0
            })
        ));
    }

    #[test]
    fn rejects_truncated_extended_length() {
        // EOF=0 and long-match symbol 271=1.  The raw 0xff escape is present,
        // but its following 16-bit adjusted length is missing.
        let encoded = spec_stream(&[(256, 1), (271, 1)], &[0x00, 0x80, 0, 0, 0xff]);
        assert!(matches!(
            decompress(&encoded, 18, 18),
            Err(CodecError::Truncated("16-bit match length"))
        ));
    }

    #[test]
    fn enforces_expected_and_maximum_sizes() {
        let encoded = compress(b"bounded").unwrap();
        assert!(matches!(
            decompress(&encoded, 7, 6),
            Err(CodecError::ExpectedSizeExceedsLimit {
                expected: 7,
                limit: 6
            })
        ));
        assert!(decompress(&encoded, 6, 7).is_err());
        assert!(decompress(&encoded, 8, 8).is_err());
    }

    #[test]
    fn rejects_trailing_bytes_after_eof() {
        let mut encoded = compress(b"A").unwrap();
        encoded.push(0);
        assert!(decompress(&encoded, 1, 1).is_err());
    }

    #[test]
    fn every_byte_value_round_trips() {
        let original: Vec<u8> = (0u8..=u8::MAX).cycle().take(4096).collect();
        let encoded = compress(&original).unwrap();
        assert_eq!(
            decompress(&encoded, original.len(), original.len()),
            Ok(original)
        );
    }
}
