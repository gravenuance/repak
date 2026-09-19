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

/// Oodle is the `COMPRESS_Custom` (ECompressionFlags 0x04) codec used by legacy UE4 paks
/// such as Days Gone's, so a reader with no Oodle decompressor can't open them at all.
/// `oodle_loader` is deliberately not used here: it pins one exact DLL build by SHA1 and
/// downloads it over the network when absent, neither of which suits an offline library
/// embedded in a desktop app. Instead this loads whatever `oo2core_9_win64.dll` sits next
/// to the host executable (or wherever `REPAK_OODLE_DLL` points) and fails soft - a pak
/// that needs Oodle then reports `OodleFailed` rather than silently producing garbage.
mod oodle {
    use std::os::raw::c_void;
    use std::sync::OnceLock;

    type OodleLZDecompress = unsafe extern "win64" fn(
        *const c_void,
        isize,
        *mut c_void,
        isize,
        i32,
        i32,
        i32,
        *mut c_void,
        isize,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        isize,
        i32,
    ) -> isize;

    static OODLE: OnceLock<Option<(libloading::Library, OodleLZDecompress)>> = OnceLock::new();

    fn candidate_paths() -> Vec<std::path::PathBuf> {
        let mut paths = vec![];
        if let Ok(explicit) = std::env::var("REPAK_OODLE_DLL") {
            paths.push(std::path::PathBuf::from(explicit));
        }
        if let Ok(exe) = std::env::current_exe() {
            paths.push(exe.with_file_name("oo2core_9_win64.dll"));
        }
        paths.push(std::path::PathBuf::from("oo2core_9_win64.dll"));
        paths
    }

    fn library() -> Option<&'static (libloading::Library, OodleLZDecompress)> {
        OODLE
            .get_or_init(|| {
                candidate_paths().into_iter().find_map(|p| unsafe {
                    let lib = libloading::Library::new(&p).ok()?;
                    let sym = *lib
                        .get::<OodleLZDecompress>(b"OodleLZ_Decompress\0")
                        .ok()?;
                    Some((lib, sym))
                })
            })
            .as_ref()
    }

    fn decompress(comp_buf: &[u8], raw_buf: &mut [u8]) -> i32 {
        let Some((_lib, f)) = library() else { return 0 };
        // fuzz_safe=1, check_crc=0, verbosity=0, thread_phase=3 (unthreaded) - the same
        // argument set retoc/oodle_loader use for reading pak chunks.
        unsafe {
            f(
                comp_buf.as_ptr() as *const c_void,
                comp_buf.len() as isize,
                raw_buf.as_mut_ptr() as *mut c_void,
                raw_buf.len() as isize,
                1,
                0,
                0,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                3,
            ) as i32
        }
    }

    pub fn getter() -> Result<repak::oodle::OodleDecompress, Box<dyn std::error::Error>> {
        if library().is_none() {
            return Err("oo2core_9_win64.dll not found next to the host executable".into());
        }
        Ok(decompress)
    }
}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_new() -> *mut PakBuilder {
    let builder = PakBuilder::new().oodle(oodle::getter);
    Box::into_raw(Box::new(builder))
}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_drop(builder: *mut PakBuilder) {
    drop(Box::from_raw(builder))
}
#[no_mangle]
pub unsafe extern "C" fn pak_reader_drop(reader: *mut PakReader) {
    drop(Box::from_raw(reader))
}
#[no_mangle]
pub unsafe extern "C" fn pak_writer_drop(writer: *mut PakWriter<Stream>) {
    drop(Box::from_raw(writer))
}
#[no_mangle]
pub unsafe extern "C" fn pak_buffer_drop(buf: *mut u8, len: usize) {
    drop(Box::from_raw(std::slice::from_raw_parts_mut(buf, len)));
}
#[no_mangle]
pub unsafe extern "C" fn pak_cstring_drop(cstring: *mut c_char) {
    drop(CString::from_raw(cstring))
}

#[no_mangle]
pub unsafe extern "C" fn pak_builder_key(
    builder: *mut PakBuilder,
    key: &[u8; 32],
) -> *mut PakBuilder {
    use repak::encryption::KeyInit;
    let builder =
        Box::from_raw(builder).key(repak::encryption::Aes256::new_from_slice(key).unwrap());
    Box::into_raw(Box::new(builder))
}

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

#[no_mangle]
pub unsafe extern "C" fn pak_builder_reader(
    builder: *mut PakBuilder,
    ctx: StreamCallbacks,
) -> *mut PakReader {
    let mut stream = Stream::new(ctx);
    match Box::from_raw(builder).reader(&mut stream) {
        Ok(reader) => Box::into_raw(Box::new(reader)),
        Err(_) => {
            std::ptr::null_mut()
        }
    }
}

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
#[no_mangle]
pub unsafe extern "C" fn pak_drop_files(buf: *mut *mut c_char, len: usize) {
    let boxed_slice: Box<[*mut c_char]> = Box::from_raw(std::slice::from_raw_parts_mut(buf, len));

    for i in 0..len {
        if !boxed_slice[i].is_null() {
            drop(CString::from_raw(boxed_slice[i]));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_file(
    writer: *mut PakWriter<Stream>,
    path: *const c_char,
    data: *const u8,
    data_len: usize,
) -> i32 {
    let path = unsafe { CStr::from_ptr(path) }.to_str().unwrap();
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    match unsafe { &mut *writer }.write_file(path, data) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn pak_writer_write_index(writer: *mut PakWriter<Stream>) -> i32 {
    match unsafe { Box::from_raw(writer) }.write_index() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
