mod oodle;

use repak::Compression;
use repak::PakBuilder;
use repak::PakReader;
use repak::PakWriter;
use repak::Version;
use std::ffi::CString;
use std::io::Read;
use std::io::SeekFrom;

use std::ffi::CStr;
use std::io::{Seek, Write};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct StreamCallbacks {
    context: *mut c_void,
    read: extern "C" fn(*mut c_void, *mut u8, usize) -> isize,
    write: extern "C" fn(*mut c_void, *const u8, usize) -> isize,
    seek: extern "C" fn(*mut c_void, i64, i32) -> i64,
    flush: extern "C" fn(*mut c_void) -> i32,
}

pub struct Stream {
    callbacks: StreamCallbacks,
}

impl Stream {
    pub fn new(callbacks: StreamCallbacks) -> Self {
        Stream { callbacks }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = (self.callbacks.read)(self.callbacks.context, buf.as_mut_ptr(), buf.len());
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result as i32))
        } else {
            Ok(result as usize)
        }
    }
}
impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result = (self.callbacks.write)(self.callbacks.context, buf.as_ptr(), buf.len());
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result as i32))
        } else {
            Ok(result as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let result = (self.callbacks.flush)(self.callbacks.context);
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result))
        } else {
            Ok(())
        }
    }
}

impl Seek for Stream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(offset) => (offset as i64, 0),
            SeekFrom::End(offset) => (offset, 2),
            SeekFrom::Current(offset) => (offset, 1),
        };
        let result = (self.callbacks.seek)(self.callbacks.context, offset, whence);
        if result < 0 {
            Err(std::io::Error::from_raw_os_error(result as i32))
        } else {
            Ok(result as u64)
        }
    }
}

/// Creates a builder that reads Oodle entries through the host's own `oo2core` DLL
/// (see the `oodle` module); the library never downloads one.
#[no_mangle]
pub extern "C" fn pak_builder_new() -> *mut PakBuilder {
    Box::into_raw(Box::new(PakBuilder::new().oodle(oodle::getter)))
}

/// Frees a builder that was never consumed by `pak_builder_reader` or `pak_builder_writer`.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_drop(builder: *mut PakBuilder) {
    drop(Box::from_raw(builder))
}
/// Frees a reader.
///
/// # Safety
///
/// `reader` must come from `pak_builder_reader` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_drop(reader: *mut PakReader) {
    drop(Box::from_raw(reader))
}
/// Frees a writer that `pak_writer_write_index` has not consumed.
///
/// # Safety
///
/// `writer` must come from `pak_builder_writer` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_writer_drop(writer: *mut PakWriter<Stream>) {
    drop(Box::from_raw(writer))
}
/// Frees a buffer returned by `pak_reader_get`.
///
/// # Safety
///
/// `buf` and `len` must be exactly the pointer and length that call returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn pak_buffer_drop(buf: *mut u8, len: usize) {
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf, len)));
}
/// Frees a string returned by this library.
///
/// # Safety
///
/// `cstring` must be a pointer this library returned (`pak_reader_mount_point` or an error message), freed once.
#[no_mangle]
pub unsafe extern "C" fn pak_cstring_drop(cstring: *mut c_char) {
    drop(CString::from_raw(cstring))
}

/// Sets the AES key and returns the builder to continue with; the old pointer is consumed.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_key(
    builder: *mut PakBuilder,
    key: &[u8; 32],
) -> *mut PakBuilder {
    use aes::cipher::KeyInit;
    let builder = Box::from_raw(builder).key(aes::Aes256::new_from_slice(key).unwrap());
    Box::into_raw(Box::new(builder))
}

/// Sets the allowed compression methods and returns the builder to continue with; the old pointer is consumed.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, and `compressions` must point to `length` valid `Compression` bytes.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_compression(
    builder: *mut PakBuilder,
    compressions: *const Compression,
    length: usize,
) -> *mut PakBuilder {
    let compressions = std::slice::from_raw_parts(compressions, length);
    let builder = Box::from_raw(builder).compression(compressions.to_vec());
    Box::into_raw(Box::new(builder))
}

/// Opens a reader on `ctx`, consuming the builder; returns null on failure.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, and `ctx`'s callbacks must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_reader(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
) -> *mut PakReader {
    let mut stream = Stream::new(ctx);
    match Box::from_raw(builder).reader(&mut stream) {
        Ok(reader) => Box::into_raw(Box::new(reader)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Creates a writer on `ctx`, consuming the builder.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, `mount_point` must be a valid NUL-terminated UTF-8 string, and `ctx`'s callbacks must stay valid until the writer is dropped or its index is written.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_writer(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
    version: repak::Version,
    mount_point: *const c_char,
    path_hash_seed: u64,
) -> *mut PakWriter<Stream> {
    let mount_point = CStr::from_ptr(mount_point).to_str().unwrap();
    let stream = Stream::new(ctx);
    let writer = Box::from_raw(builder).writer(
        stream,
        version,
        mount_point.to_string(),
        Some(path_hash_seed),
    );
    Box::into_raw(Box::new(writer))
}

#[no_mangle]
pub extern "C" fn pak_reader_version(reader: &PakReader) -> Version {
    reader.version()
}

#[no_mangle]
pub extern "C" fn pak_reader_mount_point(reader: &PakReader) -> *const c_char {
    CString::new(reader.mount_point()).unwrap().into_raw()
}

/// Reads one entry through `ctx`. Returns 0 and sets `buffer` and `length` on success; returns 1 and sets `error_message` otherwise.
///
/// # Safety
///
/// `path` must be a valid NUL-terminated UTF-8 string, `buffer`, `length` and `error_message` must be valid for writes, and `ctx`'s callbacks must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_get(
    reader: &PakReader,
    path: *const c_char,
    ctx: StreamCallbacks,
    buffer: &mut *mut u8,
    length: &mut usize,
    error_message: &mut *mut c_char,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    *error_message = std::ptr::null_mut();
    match reader.get(path, &mut Stream::new(ctx)) {
        Ok(data) => {
            let buf = data.into_boxed_slice();
            let len = buf.len();
            *buffer = Box::into_raw(buf) as *mut u8;
            *length = len;
            0
        }
        Err(e) => {
            // Every failure used to collapse to a bare "1" here, with the caller unable to
            // tell "entry not found" from "found but failed to decompress" from anything
            // else - real errors (like UnknownCompressionSlot) were being thrown away right
            // at this boundary, before the C# side even got a chance to lose them again.
            // CString::new only fails on an embedded NUL, which a normal error Display
            // string won't contain; fall back to an empty message rather than unwrap and
            // risk a second panic while already handling the first error.
            *error_message = CString::new(e.to_string())
                .unwrap_or_else(|_| CString::new("").unwrap())
                .into_raw();
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn pak_reader_files(reader: &PakReader, len: &mut usize) -> *mut *mut c_char {
    let c_files: Vec<*mut c_char> = reader
        .files()
        .into_iter()
        .map(|file| CString::new(file).unwrap().into_raw())
        .collect();
    let buf: Box<[*mut c_char]> = c_files.into_boxed_slice();
    *len = buf.len();
    Box::into_raw(buf) as *mut *mut c_char
}
/// Frees the list returned by `pak_reader_files`.
///
/// # Safety
///
/// `buf` and `len` must be exactly the pointer and length that call returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn pak_drop_files(buf: *mut *mut c_char, len: usize) {
    let boxed_slice: Box<[*mut c_char]> =
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf, len));

    for i in 0..len {
        if !boxed_slice[i].is_null() {
            drop(CString::from_raw(boxed_slice[i]));
        }
    }
}

/// Writes one file, compressed with the builder's allowed methods.
///
/// # Safety
///
/// `writer` must come from `pak_builder_writer`, `path` must be a valid NUL-terminated UTF-8 string, and `data` must point to `data_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_file(
    writer: *mut PakWriter<Stream>,
    path: *const c_char,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    match unsafe { &mut *writer }.write_file(path, true, data) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Writes the index and consumes the writer.
///
/// # Safety
///
/// `writer` must come from `pak_builder_writer` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_index(writer: *mut PakWriter<Stream>) -> i32 {
    match unsafe { Box::from_raw(writer) }.write_index() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
