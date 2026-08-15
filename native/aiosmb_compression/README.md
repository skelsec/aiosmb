# aiosmb-compression

`aiosmb-compression` is an optional, separately built Python extension for the
unchained SMB 3.1.1 compression formats: Microsoft LZNT1, XPRESS Plain LZ77,
XPRESS LZ77+Huffman, and raw LZ4 blocks. The codecs are implemented in safe
Rust from [MS-XCA] and the [LZ4 block format] without external codec
dependencies.

## Python support

The extension targets CPython 3.9 and newer. It uses PyO3's CPython 3.9 stable
ABI (`abi3-py39`), so release wheels can be reused by newer supported CPython
versions on the same platform. Repository CI validates Linux x86-64 wheels.
Other platforms require a source build unless a matching release wheel is
published. PyPy is not currently a tested target.

## Build and install

Rust 1.86 or newer and a supported Python interpreter are required.

```console
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip "maturin>=1.14,<2"
maturin develop --release
```

The source tree is also directly installable by pip:

```console
python -m pip install .
```

Build a wheel without installing it:

```console
maturin build --release
```

## API

```python
from aiosmb_compression import compress_lz4, decompress_lz4

plain = b"abc" * 100
encoded = compress_lz4(plain)
decoded = decompress_lz4(
    encoded,
    expected_size=len(plain),
    max_output_size=1024 * 1024,
)
assert decoded == plain
```

Each codec has matching functions:

- `compress_lznt1` / `decompress_lznt1`
- `compress_lz77` / `decompress_lz77`
- `compress_lz77_huffman` / `decompress_lz77_huffman`
- `compress_lz4` / `decompress_lz4`

Compressors accept `data: bytes` and produce deterministic streams.
Decompressors accept `(data, expected_size, max_output_size)`, strictly
validate the stream, and return exactly `expected_size` bytes.

Both functions copy the Python input and then detach from the GIL for the
codec work. Invalid sizes and streams raise `ValueError`. Decode rejects
truncation, invalid back-references, integer overflow, output beyond either
declared bound, and terminal streams whose decoded size differs from
`expected_size`.

## Implementation

LZNT1 uses independent 4 KiB chunks, XPRESS Huffman uses canonical tables over
64 KiB blocks, and LZ4 uses the raw block format rather than the framed
container. All LZ-style match copies support overlapping back-references.
Deterministic bounded hash chains cap match-search work without changing any
wire format.

The crate root uses `#![forbid(unsafe_code)]`.

Pattern_V1 is deliberately absent: MS-SMB2 permits it only in chained
compression transforms, while this package currently targets unchained
transforms.

## Development

```console
cargo fmt --all --check
cargo test
cargo bench
```

`cargo test` includes deterministic Microsoft vectors, boundary cases, and
property-based round trips. Criterion prints measurements for review; the
benchmarks deliberately have no pass/fail throughput threshold.

Fuzzing requires `cargo-fuzz` and a nightly Rust toolchain:

```console
cargo +nightly fuzz run decode
cargo +nightly fuzz run round_trip
cargo +nightly fuzz run decode_all
cargo +nightly fuzz run round_trip_all
```

[MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
[LZ4 block format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
