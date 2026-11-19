mod oodle;

use repak::Compression;
use repak::PakBuilder;
use repak::PakReader;
use repak::PakVariant;
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

/// The wire values of `repak::PakVariant`, matching the C# `PakVariant` enum.
fn variant_from_byte(variant: u8) -> Option<PakVariant> {
    match variant {
        0 => Some(PakVariant::Standard),
        1 => Some(PakVariant::MarvelRivals),
        _ => None,
    }
}

/// Selects a game's pak format variant (0 standard, 1 Marvel Rivals) and returns the builder
/// to continue with; the old pointer is consumed. Returns null, with the builder freed, for a
/// value that is no variant. Builders default to the standard variant.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_variant(
    builder: *mut PakBuilder,
    variant: u8,
) -> *mut PakBuilder {
    let builder = Box::from_raw(builder);
    match variant_from_byte(variant) {
        Some(variant) => Box::into_raw(Box::new(builder.variant(variant))),
        None => std::ptr::null_mut(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    type Memory = Cursor<Vec<u8>>;

    extern "C" fn read(context: *mut c_void, buf: *mut u8, len: usize) -> isize {
        // SAFETY: `context` is the `Memory` the test passes in `callbacks`, and `buf` is valid for `len`.
        let (memory, buf) = unsafe {
            (
                &mut *context.cast::<Memory>(),
                std::slice::from_raw_parts_mut(buf, len),
            )
        };
        memory.read(buf).map_or(-1, |n| n as isize)
    }

    extern "C" fn write(context: *mut c_void, buf: *const u8, len: usize) -> isize {
        // SAFETY: as in `read`.
        let (memory, buf) = unsafe {
            (
                &mut *context.cast::<Memory>(),
                std::slice::from_raw_parts(buf, len),
            )
        };
        memory.write(buf).map_or(-1, |n| n as isize)
    }

    extern "C" fn seek(context: *mut c_void, offset: i64, whence: i32) -> i64 {
        // SAFETY: as in `read`.
        let memory = unsafe { &mut *context.cast::<Memory>() };
        let target = match whence {
            0 => SeekFrom::Start(offset as u64),
            1 => SeekFrom::Current(offset),
            _ => SeekFrom::End(offset),
        };
        memory.seek(target).map_or(-1, |at| at as i64)
    }

    extern "C" fn flush(_context: *mut c_void) -> i32 {
        0
    }

    fn callbacks(memory: &mut Memory) -> StreamCallbacks {
        StreamCallbacks {
            context: (memory as *mut Memory).cast(),
            read,
            write,
            seek,
            flush,
        }
    }

    const KEY: [u8; 32] = [7; 32];

    /// A builder with the key and variant set, as a C# caller would build it.
    unsafe fn builder(variant: u8) -> *mut PakBuilder {
        let builder = pak_builder_key(pak_builder_new(), &KEY);
        pak_builder_variant(builder, variant)
    }

    fn contents() -> Vec<u8> {
        b"some file contents".repeat(100)
    }

    fn write_pak(variant: u8) -> Memory {
        let contents = contents();
        let mut memory = Memory::new(vec![]);
        // SAFETY: every pointer comes from this library or the locals above and outlives its call.
        unsafe {
            let writer = pak_builder_writer(
                builder(variant),
                callbacks(&mut memory),
                Version::V11,
                c"../../../".as_ptr(),
                0,
            );
            let result = pak_writer_write_file(
                writer,
                c"a/file.txt".as_ptr(),
                contents.as_ptr(),
                contents.len(),
            );
            assert_eq!(result, 0);
            assert_eq!(pak_writer_write_index(writer), 0);
        }
        memory
    }

    /// The entry's bytes, or None when the pak or the entry cannot be read.
    fn read_pak(variant: u8, memory: &mut Memory) -> Option<Vec<u8>> {
        // SAFETY: as in `write_pak`; the buffer is freed with the matching drop.
        unsafe {
            let reader = pak_builder_reader(builder(variant), callbacks(memory));
            if reader.is_null() {
                return None;
            }
            let (mut buffer, mut length, mut error) =
                (std::ptr::null_mut(), 0, std::ptr::null_mut());
            let result = pak_reader_get(
                &*reader,
                c"a/file.txt".as_ptr(),
                callbacks(memory),
                &mut buffer,
                &mut length,
                &mut error,
            );
            pak_reader_drop(reader);
            if result != 0 {
                pak_cstring_drop(error);
                return None;
            }
            let data = std::slice::from_raw_parts(buffer, length).to_vec();
            pak_buffer_drop(buffer, length);
            Some(data)
        }
    }

    #[test]
    fn marvel_rivals_pak_round_trips_through_the_c_api() {
        let mut memory = write_pak(1);
        assert_eq!(read_pak(1, &mut memory), Some(contents()));
    }

    #[test]
    fn standard_variant_does_not_read_a_marvel_rivals_pak() {
        let mut memory = write_pak(1);
        assert_ne!(read_pak(0, &mut memory), Some(contents()));
    }

    #[test]
    fn variant_that_is_not_one_yields_no_builder() {
        // SAFETY: the builder comes from this library and is consumed by the call.
        assert!(unsafe { pak_builder_variant(pak_builder_new(), 2) }.is_null());
    }

    #[test]
    fn variant_bytes_map_to_the_variants() {
        assert_eq!(variant_from_byte(0), Some(PakVariant::Standard));
        assert_eq!(variant_from_byte(1), Some(PakVariant::MarvelRivals));
        assert_eq!(variant_from_byte(255), None);
    }
}
