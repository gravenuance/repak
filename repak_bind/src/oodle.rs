//! Oodle is the `COMPRESS_Custom` (ECompressionFlags 0x04) codec of legacy UE4 paks such as
//! Days Gone's. It is proprietary and the host (UAssetEditor, see its ADR 0001) supplies its own
//! copy, so this loads `OodleLZ_Decompress` from the DLL that `REPAK_OODLE_DLL` names and never
//! touches the network. Only that absolute path is tried: no search of the executable's folder,
//! the working folder or `PATH`, where a planted DLL could load instead of the host's validated
//! one. A successful load is kept for the process; a failure is not, so a host that fixes the
//! variable is picked up on the next read.

use std::ffi::OsString;
use std::os::raw::c_void;
use std::path::Path;
use std::sync::OnceLock;

pub const ENV_VAR: &str = "REPAK_OODLE_DLL";

// "system" is the Windows calling convention for the Windows DLL and the platform's C one for
// Oodle's native libraries, so the module builds on every target (`win64` exists only on x86-64).
type OodleLzDecompress = unsafe extern "system" fn(
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

pub(crate) struct Loaded {
    // Keeps the DLL mapped for as long as `decompress` may be called.
    _library: libloading::Library,
    decompress: OodleLzDecompress,
}

static OODLE: OnceLock<Loaded> = OnceLock::new();

fn load(path: &Path) -> Option<Loaded> {
    // A relative path would make the loader search the working folder and PATH.
    if !path.is_absolute() {
        return None;
    }
    // SAFETY: loading a library runs its initialisers; the host validated this path and
    // accepts running the Oodle DLL it points at (ADR 0001).
    unsafe {
        let library = libloading::Library::new(path).ok()?;
        let decompress = *library
            .get::<OodleLzDecompress>(b"OodleLZ_Decompress\0")
            .ok()?;
        Some(Loaded {
            _library: library,
            decompress,
        })
    }
}

/// The loaded library, loading it from the path `variable()` gives if none is loaded yet.
fn library_in(
    cell: &OnceLock<Loaded>,
    variable: impl FnOnce() -> Option<OsString>,
) -> Option<&Loaded> {
    if let Some(loaded) = cell.get() {
        return Some(loaded);
    }
    let loaded = load(Path::new(&variable()?))?;
    Some(cell.get_or_init(|| loaded))
}

fn library() -> Option<&'static Loaded> {
    library_in(&OODLE, || std::env::var_os(ENV_VAR))
}

fn decompress(comp_buf: &[u8], raw_buf: &mut [u8]) -> i32 {
    let Some(loaded) = library() else { return 0 };
    // fuzz_safe=1, check_crc=0, verbosity=0, thread_phase=3 (unthreaded), the argument set
    // oodle_loader uses for reading pak chunks.
    //
    // SAFETY: `decompress` is OodleLZ_Decompress and the two buffers are valid for the
    // lengths passed.
    unsafe {
        (loaded.decompress)(
            comp_buf.as_ptr().cast(),
            comp_buf.len() as isize,
            raw_buf.as_mut_ptr().cast(),
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

fn require(loaded: Option<&Loaded>) -> Result<repak::OodleDecompress, Box<dyn std::error::Error>> {
    match loaded {
        Some(_) => Ok(decompress),
        None => Err(format!("{ENV_VAR} is unset or does not name a loadable Oodle DLL").into()),
    }
}

/// `getter` with the cache and the DLL path supplied by the caller instead of the process-wide
/// cache and the environment.
pub(crate) fn getter_in(
    cell: &OnceLock<Loaded>,
    variable: impl FnOnce() -> Option<OsString>,
) -> Result<repak::OodleDecompress, Box<dyn std::error::Error>> {
    require(library_in(cell, variable))
}

/// The getter handed to `PakBuilder::oodle`; fails when the DLL does not load.
pub fn getter() -> Result<repak::OodleDecompress, Box<dyn std::error::Error>> {
    getter_in(&OODLE, || std::env::var_os(ENV_VAR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::path::PathBuf;

    fn absolute_missing() -> OsString {
        std::env::temp_dir()
            .join("repak_bind_no_such_oo2core_9_win64.dll")
            .into_os_string()
    }

    #[test]
    fn unset_variable_loads_nothing() {
        assert!(library_in(&OnceLock::new(), || None).is_none());
    }

    #[test]
    fn missing_file_loads_nothing() {
        assert!(library_in(&OnceLock::new(), || Some(absolute_missing())).is_none());
    }

    #[test]
    fn file_that_is_not_a_library_loads_nothing() {
        let not_a_dll = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(library_in(&OnceLock::new(), || Some(not_a_dll.into_os_string())).is_none());
    }

    #[test]
    fn relative_path_is_never_handed_to_the_loader() {
        // A bare name would make the OS loader search the working folder and PATH.
        let not_absolute = OsString::from("oo2core_9_win64.dll");
        assert!(library_in(&OnceLock::new(), || Some(not_absolute)).is_none());
    }

    #[test]
    fn each_call_after_a_failure_reads_the_variable_again() {
        let cell = OnceLock::new();
        let reads = Cell::new(0);
        for _ in 0..3 {
            let loaded = library_in(&cell, || {
                reads.set(reads.get() + 1);
                Some(absolute_missing())
            });
            assert!(loaded.is_none());
        }
        assert_eq!(reads.get(), 3);
    }

    #[test]
    fn no_library_is_the_error_the_core_reports_as_a_missing_oodle_pointer() {
        let error = require(None).err().unwrap();
        assert!(error.to_string().contains(ENV_VAR), "{error}");
    }
}
