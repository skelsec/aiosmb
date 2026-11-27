#![forbid(unsafe_code)]

mod codec;
pub mod lz4;
pub mod lz77_huffman;
pub mod lznt1;

use pyo3::Bound;
use pyo3::Py;
use pyo3::PyAny;
use pyo3::PyResult;
use pyo3::Python;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::PyModule;
use pyo3::types::{PyAnyMethods, PyBytes, PyBytesMethods, PyModuleMethods};
use pyo3::wrap_pyfunction;

pub use codec::CodecError;
pub use codec::compress;
pub use codec::decompress;

type Compressor = fn(&[u8]) -> Result<Vec<u8>, CodecError>;
type Decompressor = fn(&[u8], usize, usize) -> Result<Vec<u8>, CodecError>;

/// Compress bytes using the MS-XCA XPRESS Plain LZ77 stream format.
#[pyo3::pyfunction]
fn compress_lz77(py: Python<'_>, data: &Bound<'_, PyBytes>) -> PyResult<Py<PyBytes>> {
    compress_with(py, data, codec::compress)
}

/// Decompress an MS-XCA XPRESS Plain LZ77 stream with strict size bounds.
#[pyo3::pyfunction]
#[pyo3(signature = (data, expected_size, max_output_size))]
fn decompress_lz77(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    expected_size: &Bound<'_, PyAny>,
    max_output_size: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    decompress_with(py, data, expected_size, max_output_size, codec::decompress)
}

/// Compress bytes using the MS-XCA LZNT1 stream format.
#[pyo3::pyfunction]
fn compress_lznt1(py: Python<'_>, data: &Bound<'_, PyBytes>) -> PyResult<Py<PyBytes>> {
    compress_with(py, data, lznt1::compress)
}

/// Decompress an MS-XCA LZNT1 stream with strict size bounds.
#[pyo3::pyfunction]
#[pyo3(signature = (data, expected_size, max_output_size))]
fn decompress_lznt1(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    expected_size: &Bound<'_, PyAny>,
    max_output_size: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    decompress_with(py, data, expected_size, max_output_size, lznt1::decompress)
}

/// Compress bytes using the MS-XCA XPRESS LZ77+Huffman stream format.
#[pyo3::pyfunction]
fn compress_lz77_huffman(py: Python<'_>, data: &Bound<'_, PyBytes>) -> PyResult<Py<PyBytes>> {
    compress_with(py, data, lz77_huffman::compress)
}

/// Decompress an MS-XCA XPRESS LZ77+Huffman stream with strict size bounds.
#[pyo3::pyfunction]
#[pyo3(signature = (data, expected_size, max_output_size))]
fn decompress_lz77_huffman(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    expected_size: &Bound<'_, PyAny>,
    max_output_size: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    decompress_with(
        py,
        data,
        expected_size,
        max_output_size,
        lz77_huffman::decompress,
    )
}

/// Compress bytes using the raw LZ4 block format used by SMB 3.1.1.
#[pyo3::pyfunction]
fn compress_lz4(py: Python<'_>, data: &Bound<'_, PyBytes>) -> PyResult<Py<PyBytes>> {
    compress_with(py, data, lz4::compress)
}

/// Decompress a raw LZ4 block with strict size bounds.
#[pyo3::pyfunction]
#[pyo3(signature = (data, expected_size, max_output_size))]
fn decompress_lz4(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    expected_size: &Bound<'_, PyAny>,
    max_output_size: &Bound<'_, PyAny>,
) -> PyResult<Py<PyBytes>> {
    decompress_with(py, data, expected_size, max_output_size, lz4::decompress)
}

fn compress_with(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    codec: Compressor,
) -> PyResult<Py<PyBytes>> {
    // Python-owned memory cannot be accessed after detaching from the GIL, so
    // take an owned snapshot before entering the compute-only closure.
    let input = data.as_bytes().to_vec();
    let compressed = py
        .detach(move || codec(&input))
        .map_err(codec_value_error)?;
    Ok(PyBytes::new(py, &compressed).unbind())
}

fn decompress_with(
    py: Python<'_>,
    data: &Bound<'_, PyBytes>,
    expected_size: &Bound<'_, PyAny>,
    max_output_size: &Bound<'_, PyAny>,
    codec: Decompressor,
) -> PyResult<Py<PyBytes>> {
    let expected_size = nonnegative_size(expected_size, "expected_size")?;
    let max_output_size = nonnegative_size(max_output_size, "max_output_size")?;
    let input = data.as_bytes().to_vec();
    let decompressed = py
        .detach(move || codec(&input, expected_size, max_output_size))
        .map_err(codec_value_error)?;
    Ok(PyBytes::new(py, &decompressed).unbind())
}

fn nonnegative_size(value: &Bound<'_, PyAny>, name: &str) -> PyResult<usize> {
    value.extract::<usize>().map_err(|_| {
        PyValueError::new_err(format!(
            "{name} must be a non-negative integer that fits in usize"
        ))
    })
}

fn codec_value_error(error: CodecError) -> pyo3::PyErr {
    PyValueError::new_err(error.to_string())
}

#[pyo3::pymodule]
fn aiosmb_compression(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(compress_lz77, module)?)?;
    module.add_function(wrap_pyfunction!(decompress_lz77, module)?)?;
    module.add_function(wrap_pyfunction!(compress_lznt1, module)?)?;
    module.add_function(wrap_pyfunction!(decompress_lznt1, module)?)?;
    module.add_function(wrap_pyfunction!(compress_lz77_huffman, module)?)?;
    module.add_function(wrap_pyfunction!(decompress_lz77_huffman, module)?)?;
    module.add_function(wrap_pyfunction!(compress_lz4, module)?)?;
    module.add_function(wrap_pyfunction!(decompress_lz4, module)?)?;
    Ok(())
}
