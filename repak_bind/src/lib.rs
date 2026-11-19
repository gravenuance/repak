//! C API over repak for the C# wrapper. Every export runs its body through `boundary::guard`
//! and checks what it is handed: null pointers, strings that are not UTF-8, and enum values
//! passed as raw bytes all become an error return (null, or status 1) with a message, never a
//! panic or undefined behaviour. `pak_last_error` returns the message of the calling thread's
//! most recent failure.

mod boundary;
mod oodle;
mod stream;

use boundary::{
    borrow, borrow_mut, guard, publish_error, slice_arg, status, str_arg, take_box,
    take_last_error, BindResult,
};
use repak::{Compression, PakBuilder, PakReader, PakVariant, PakWriter, Version};
use std::ffi::{c_char, CString};
pub use stream::{Stream, StreamCallbacks};

fn compression_from_byte(compression: u8) -> Option<Compression> {
    match compression {
        0 => Some(Compression::Zlib),
        1 => Some(Compression::Gzip),
        2 => Some(Compression::Oodle),
        3 => Some(Compression::Zstd),
        4 => Some(Compression::LZ4),
        _ => None,
    }
}

fn variant_from_byte(variant: u8) -> Option<PakVariant> {
    match variant {
        0 => Some(PakVariant::Standard),
        1 => Some(PakVariant::MarvelRivals),
        _ => None,
    }
}

fn describe<E: std::fmt::Display>(error: E) -> String {
    error.to_string()
}

/// Takes this thread's most recent error message, or null if there is none. The caller frees it
/// with `pak_cstring_drop`.
#[no_mangle]
pub extern "C" fn pak_last_error() -> *mut c_char {
    take_last_error()
}

/// Creates a builder that reads Oodle entries through the host's own `oo2core` DLL
/// (see the `oodle` module); the library never downloads one. Null on failure.
#[no_mangle]
pub extern "C" fn pak_builder_new() -> *mut PakBuilder {
    guard(|| {
        Ok(Box::into_raw(Box::new(
            PakBuilder::new().oodle(oodle::getter),
        )))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Frees a builder that was never consumed by `pak_builder_reader` or `pak_builder_writer`.
///
/// # Safety
///
/// `builder` must be null or come from this library and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_drop(builder: *mut PakBuilder) {
    let _ = guard(|| {
        if !builder.is_null() {
            drop(Box::from_raw(builder));
        }
        Ok(())
    });
}

/// Frees a reader.
///
/// # Safety
///
/// `reader` must be null or come from `pak_builder_reader` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_drop(reader: *mut PakReader) {
    let _ = guard(|| {
        if !reader.is_null() {
            drop(Box::from_raw(reader));
        }
        Ok(())
    });
}

/// Frees a writer that `pak_writer_write_index` has not consumed.
///
/// # Safety
///
/// `writer` must be null or come from `pak_builder_writer` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_writer_drop(writer: *mut PakWriter<Stream>) {
    let _ = guard(|| {
        if !writer.is_null() {
            drop(Box::from_raw(writer));
        }
        Ok(())
    });
}

/// Frees a buffer returned by `pak_reader_get`.
///
/// # Safety
///
/// `buf` and `len` must be exactly the pointer and length that call returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn pak_buffer_drop(buf: *mut u8, len: usize) {
    let _ = guard(|| {
        if !buf.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf, len)));
        }
        Ok(())
    });
}

/// Frees a string returned by this library.
///
/// # Safety
///
/// `cstring` must be null or a pointer this library returned (`pak_reader_mount_point`,
/// `pak_last_error` or an error message), freed once.
#[no_mangle]
pub unsafe extern "C" fn pak_cstring_drop(cstring: *mut c_char) {
    let _ = guard(|| {
        if !cstring.is_null() {
            drop(CString::from_raw(cstring));
        }
        Ok(())
    });
}

/// Sets the AES key and returns the builder to continue with; the old pointer is consumed.
/// Null, with the builder freed, on failure.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, and `key` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_key(
    builder: *mut PakBuilder,
    key: *const [u8; 32],
) -> *mut PakBuilder {
    use aes::cipher::KeyInit;
    guard(|| {
        let builder = take_box(builder, "builder")?;
        let key = borrow(key, "key")?;
        let cipher = aes::Aes256::new_from_slice(key).map_err(describe)?;
        Ok(Box::into_raw(Box::new(builder.key(cipher))))
    })
    .unwrap_or(std::ptr::null_mut())
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
    guard(|| {
        let builder = take_box(builder, "builder")?;
        let variant =
            variant_from_byte(variant).ok_or_else(|| format!("{variant} is not a pak variant"))?;
        Ok(Box::into_raw(Box::new(builder.variant(variant))))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Sets the allowed compression methods (0 Zlib, 1 Gzip, 2 Oodle, 3 Zstd, 4 LZ4) and returns the
/// builder to continue with; the old pointer is consumed. Returns null, with the builder freed,
/// for a value that is no compression method.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, and `compressions` must point to `length` bytes.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_compression(
    builder: *mut PakBuilder,
    compressions: *const u8,
    length: usize,
) -> *mut PakBuilder {
    guard(|| {
        let builder = take_box(builder, "builder")?;
        let compressions = slice_arg(compressions, length, "compressions")?
            .iter()
            .map(|&byte| {
                compression_from_byte(byte)
                    .ok_or_else(|| format!("{byte} is not a compression method"))
            })
            .collect::<BindResult<Vec<_>>>()?;
        Ok(Box::into_raw(Box::new(builder.compression(compressions))))
    })
    .unwrap_or(std::ptr::null_mut())
}

unsafe fn open_reader(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
    error_message: *mut *mut c_char,
) -> *mut PakReader {
    let result = guard(|| {
        let builder = take_box(builder, "builder")?;
        let reader = builder.reader(&mut Stream::new(ctx)).map_err(describe)?;
        Ok(Box::into_raw(Box::new(reader)))
    });
    publish_error(&result, error_message);
    result.unwrap_or(std::ptr::null_mut())
}

/// Opens a reader on `ctx`, consuming the builder; null on failure (see `pak_last_error`).
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, and `ctx`'s callbacks must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_reader(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
) -> *mut PakReader {
    open_reader(builder, ctx, std::ptr::null_mut())
}

/// `pak_builder_reader` that also stores the failure message in `error_message`, or null on
/// success. A message is freed with `pak_cstring_drop`.
///
/// # Safety
///
/// As `pak_builder_reader`, and `error_message` must be null or valid for a write.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_reader_ex(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
    error_message: *mut *mut c_char,
) -> *mut PakReader {
    open_reader(builder, ctx, error_message)
}

/// Creates a writer on `ctx`, consuming the builder. `version` is a `repak::Version` value
/// (0 to 12); null, with the builder freed, for anything else or any other failure.
///
/// # Safety
///
/// `builder` must come from this library and not be used afterwards, `mount_point` must be a valid NUL-terminated UTF-8 string, and `ctx`'s callbacks must stay valid until the writer is dropped or its index is written.
#[no_mangle]
pub unsafe extern "C" fn pak_builder_writer(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
    version: u8,
    mount_point: *const c_char,
    path_hash_seed: u64,
) -> *mut PakWriter<Stream> {
    guard(|| {
        let builder = take_box(builder, "builder")?;
        let version =
            Version::from_repr(version).ok_or_else(|| format!("{version} is not a pak version"))?;
        let mount_point = str_arg(mount_point, "mount_point")?;
        let writer = builder.writer(
            Stream::new(ctx),
            version,
            mount_point.to_owned(),
            Some(path_hash_seed),
        );
        Ok(Box::into_raw(Box::new(writer)))
    })
    .unwrap_or(std::ptr::null_mut())
}

/// The pak's `repak::Version` value (0 to 12), or 255 on failure.
///
/// # Safety
///
/// `reader` must come from `pak_builder_reader`.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_version(reader: *const PakReader) -> u8 {
    guard(|| Ok(borrow(reader, "reader")?.version() as u8)).unwrap_or(u8::MAX)
}

/// The pak's mount point; null on failure. Freed with `pak_cstring_drop`.
///
/// # Safety
///
/// `reader` must come from `pak_builder_reader`.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_mount_point(reader: *const PakReader) -> *const c_char {
    guard(|| {
        let mount_point = borrow(reader, "reader")?.mount_point();
        let mount_point =
            CString::new(mount_point).map_err(|_| "the mount point contains a NUL byte")?;
        Ok(mount_point.into_raw().cast_const())
    })
    .unwrap_or(std::ptr::null())
}

/// Reads one entry through `ctx`. Returns 0 and sets `buffer` and `length` on success; returns 1
/// and sets `error_message` (when not null) otherwise.
///
/// # Safety
///
/// `reader` must come from `pak_builder_reader`, `path` must be a valid NUL-terminated string, `buffer` and `length` must be valid for writes, `error_message` must be null or valid for a write, and `ctx`'s callbacks must be valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_get(
    reader: *const PakReader,
    path: *const c_char,
    ctx: StreamCallbacks,
    buffer: *mut *mut u8,
    length: *mut usize,
    error_message: *mut *mut c_char,
) -> i32 {
    let result = guard(|| {
        let reader = borrow(reader, "reader")?;
        let path = str_arg(path, "path")?;
        let buffer = borrow_mut(buffer, "buffer")?;
        let length = borrow_mut(length, "length")?;
        let data = reader
            .get(path, &mut Stream::new(ctx))
            .map_err(describe)?
            .into_boxed_slice();
        *length = data.len();
        *buffer = Box::into_raw(data).cast::<u8>();
        Ok(())
    });
    publish_error(&result, error_message);
    status(&result)
}

/// The pak's entry names, as `*length` NUL-terminated strings; null on failure. Freed with
/// `pak_drop_files`.
///
/// # Safety
///
/// `reader` must come from `pak_builder_reader`, and `length` must be valid for a write.
#[no_mangle]
pub unsafe extern "C" fn pak_reader_files(
    reader: *const PakReader,
    length: *mut usize,
) -> *mut *mut c_char {
    let result = guard(|| {
        let reader = borrow(reader, "reader")?;
        let length = borrow_mut(length, "length")?;
        let names = reader
            .files()
            .into_iter()
            .map(|name| {
                CString::new(name).map_err(|_| "an entry name contains a NUL byte".to_owned())
            })
            .collect::<BindResult<Vec<_>>>()?;
        let names: Box<[*mut c_char]> = names.into_iter().map(CString::into_raw).collect();
        *length = names.len();
        Ok(Box::into_raw(names).cast::<*mut c_char>())
    });
    if result.is_err() && !length.is_null() {
        *length = 0;
    }
    result.unwrap_or(std::ptr::null_mut())
}

/// Frees the list returned by `pak_reader_files`.
///
/// # Safety
///
/// `buf` and `len` must be exactly the pointer and length that call returned, freed once.
#[no_mangle]
pub unsafe extern "C" fn pak_drop_files(buf: *mut *mut c_char, len: usize) {
    let _ = guard(|| {
        if buf.is_null() {
            return Ok(());
        }
        let names = Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf, len));
        for &name in names.iter() {
            if !name.is_null() {
                drop(CString::from_raw(name));
            }
        }
        Ok(())
    });
}

/// Writes one file, compressed with the builder's allowed methods. 0 on success, 1 on failure.
///
/// # Safety
///
/// `writer` must come from `pak_builder_writer`, `path` must be a valid NUL-terminated string, and `data` must point to `data_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_file(
    writer: *mut PakWriter<Stream>,
    path: *const c_char,
    data: *const u8,
    data_len: usize,
) -> i32 {
    status(&guard(|| {
        let writer = borrow_mut(writer, "writer")?;
        let path = str_arg(path, "path")?;
        let data = slice_arg(data, data_len, "data")?;
        writer.write_file(path, true, data).map_err(describe)
    }))
}

/// Writes the index and consumes the writer, whatever the result. 0 on success, 1 on failure.
///
/// # Safety
///
/// `writer` must come from `pak_builder_writer` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_index(writer: *mut PakWriter<Stream>) -> i32 {
    status(&guard(|| {
        take_box(writer, "writer")?
            .write_index()
            .map(drop)
            .map_err(describe)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{c_void, CStr};
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

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

    extern "C" fn failing_write(_: *mut c_void, _: *const u8, _: usize) -> isize {
        -1
    }

    extern "C" fn oversized_write(_: *mut c_void, _: *const u8, len: usize) -> isize {
        len as isize + 1
    }

    fn callbacks(memory: &mut Memory) -> StreamCallbacks {
        StreamCallbacks {
            context: (memory as *mut Memory).cast(),
            read: Some(read),
            write: Some(write),
            seek: Some(seek),
            flush: Some(flush),
        }
    }

    fn with_write(
        memory: &mut Memory,
        write: extern "C" fn(*mut c_void, *const u8, usize) -> isize,
    ) -> StreamCallbacks {
        StreamCallbacks {
            write: Some(write),
            ..callbacks(memory)
        }
    }

    const KEY: [u8; 32] = [7; 32];
    const MOUNT: &CStr = c"../../../";

    /// The message `pak_last_error` holds, which every failing export must have set.
    fn last_error() -> String {
        let message = pak_last_error();
        assert!(!message.is_null(), "no error message was set");
        // SAFETY: the pointer came from `pak_last_error` and is freed once.
        unsafe {
            let text = CStr::from_ptr(message).to_string_lossy().into_owned();
            pak_cstring_drop(message);
            text
        }
    }

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
                Version::V11 as u8,
                MOUNT.as_ptr(),
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
                reader,
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
        assert_eq!(last_error(), "2 is not a pak variant");
    }

    #[test]
    fn variant_bytes_map_to_the_variants() {
        assert_eq!(variant_from_byte(0), Some(PakVariant::Standard));
        assert_eq!(variant_from_byte(1), Some(PakVariant::MarvelRivals));
        assert_eq!(variant_from_byte(255), None);
    }

    #[test]
    fn compression_bytes_are_the_enum_discriminants() {
        for compression in [
            Compression::Zlib,
            Compression::Gzip,
            Compression::Oodle,
            Compression::Zstd,
            Compression::LZ4,
        ] {
            assert_eq!(compression_from_byte(compression as u8), Some(compression));
        }
        assert_eq!(compression_from_byte(5), None);
    }

    #[test]
    fn version_bytes_are_the_enum_discriminants() {
        for version in Version::iter() {
            assert_eq!(Version::from_repr(version as u8), Some(version));
        }
        assert_eq!(Version::from_repr(13), None);
    }

    #[test]
    fn unknown_compression_is_an_error_not_an_enum() {
        // SAFETY: the builder comes from this library and is consumed by the call.
        let builder = unsafe { pak_builder_compression(pak_builder_new(), [0u8, 9].as_ptr(), 2) };
        assert!(builder.is_null());
        assert_eq!(last_error(), "9 is not a compression method");
    }

    #[test]
    fn unknown_version_is_an_error_not_an_enum() {
        let mut memory = Memory::new(vec![]);
        // SAFETY: the builder comes from this library and is consumed by the call.
        let writer = unsafe {
            pak_builder_writer(
                pak_builder_new(),
                callbacks(&mut memory),
                200,
                MOUNT.as_ptr(),
                0,
            )
        };
        assert!(writer.is_null());
        assert_eq!(last_error(), "200 is not a pak version");
    }

    #[test]
    fn a_path_that_is_not_utf8_is_an_error_not_a_panic() {
        let mut memory = Memory::new(vec![]);
        // SAFETY: the pointers come from this library or live for the call.
        unsafe {
            let writer = pak_builder_writer(
                pak_builder_new(),
                callbacks(&mut memory),
                Version::V11 as u8,
                MOUNT.as_ptr(),
                0,
            );
            let path = c"caf\xe9.txt";
            assert_eq!(
                pak_writer_write_file(writer, path.as_ptr(), [1u8].as_ptr(), 1),
                1
            );
            assert_eq!(last_error(), "path is not valid UTF-8");
            pak_writer_drop(writer);
        }
    }

    #[test]
    fn null_pointers_are_errors_not_crashes() {
        // SAFETY: null is what is being tested.
        unsafe {
            assert!(pak_builder_key(std::ptr::null_mut(), &KEY).is_null());
            assert_eq!(last_error(), "builder is null");
            assert_eq!(pak_writer_write_index(std::ptr::null_mut()), 1);
            assert_eq!(pak_reader_version(std::ptr::null()), u8::MAX);
            assert!(pak_reader_mount_point(std::ptr::null()).is_null());
            pak_reader_drop(std::ptr::null_mut());
            pak_buffer_drop(std::ptr::null_mut(), 0);
        }
    }

    #[test]
    fn a_pak_that_is_not_one_fails_with_a_message() {
        let mut memory = Memory::new(vec![0xAB; 300]);
        let mut error = std::ptr::null_mut();
        // SAFETY: the pointers come from this library or live for the call.
        let reader =
            unsafe { pak_builder_reader_ex(pak_builder_new(), callbacks(&mut memory), &mut error) };
        assert!(reader.is_null());
        assert!(!error.is_null());
        // SAFETY: `error` is a message this library returned.
        unsafe {
            assert!(!CStr::from_ptr(error).to_bytes().is_empty());
            pak_cstring_drop(error);
        }
    }

    #[test]
    fn a_stream_that_fails_to_write_is_an_error() {
        let mut memory = Memory::new(vec![]);
        // SAFETY: the pointers come from this library or live for the call.
        unsafe {
            let writer = pak_builder_writer(
                pak_builder_new(),
                with_write(&mut memory, failing_write),
                Version::V11 as u8,
                MOUNT.as_ptr(),
                0,
            );
            assert_eq!(
                pak_writer_write_file(writer, c"a.txt".as_ptr(), [1u8].as_ptr(), 1),
                1
            );
            assert!(last_error().contains("write stream callback failed"));
            pak_writer_drop(writer);
        }
    }

    #[test]
    fn a_stream_that_reports_too_many_bytes_is_an_error_not_a_panic() {
        let mut memory = Memory::new(vec![]);
        // SAFETY: the pointers come from this library or live for the call.
        unsafe {
            let writer = pak_builder_writer(
                pak_builder_new(),
                with_write(&mut memory, oversized_write),
                Version::V11 as u8,
                MOUNT.as_ptr(),
                0,
            );
            assert_eq!(
                pak_writer_write_file(writer, c"a.txt".as_ptr(), [1u8].as_ptr(), 1),
                1
            );
            assert!(last_error().contains("write stream callback reported"));
            pak_writer_drop(writer);
        }
    }

    /// A v11 pak whose one Zlib entry is marked Oodle in the footer, so reading it needs Oodle.
    fn oodle_marked_pak() -> Vec<u8> {
        let mut writer = PakBuilder::new().compression([Compression::Zlib]).writer(
            Cursor::new(vec![]),
            Version::V11,
            "../../../".to_owned(),
            Some(0),
        );
        writer.write_file("a.bin", true, [7u8; 64]).unwrap();
        let mut bytes = writer.write_index().unwrap().into_inner();
        let at = bytes
            .windows(5)
            .rposition(|window| window == b"Zlib\0")
            .unwrap();
        bytes[at..at + 6].copy_from_slice(b"Oodle\0");
        bytes
    }

    #[test]
    fn an_oodle_entry_without_a_loadable_dll_says_why() {
        let mut memory = Memory::new(oodle_marked_pak());
        let missing = std::env::temp_dir().join("repak_bind_no_such_oo2core_9_win64.dll");
        std::env::set_var(oodle::ENV_VAR, missing);
        let (mut buffer, mut length, mut error) = (std::ptr::null_mut(), 0, std::ptr::null_mut());
        // SAFETY: the pointers come from this library or live for the call.
        let result = unsafe {
            let reader = pak_builder_reader(pak_builder_new(), callbacks(&mut memory));
            assert!(!reader.is_null());
            let result = pak_reader_get(
                reader,
                c"a.bin".as_ptr(),
                callbacks(&mut memory),
                &mut buffer,
                &mut length,
                &mut error,
            );
            pak_reader_drop(reader);
            result
        };
        std::env::remove_var(oodle::ENV_VAR);
        assert_eq!(result, 1);
        // SAFETY: `error` is a message this library returned.
        let message = unsafe {
            let message = CStr::from_ptr(error).to_string_lossy().into_owned();
            pak_cstring_drop(error);
            message
        };
        assert!(
            message.starts_with("pointer to OodleLZ_Decompress was not provided: "),
            "{message}"
        );
        assert!(message.contains(oodle::ENV_VAR), "{message}");
    }
}
