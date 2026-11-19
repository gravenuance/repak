//! Oodle is the `COMPRESS_Custom` (ECompressionFlags 0x04) codec of legacy UE4 paks such as
//! Days Gone's. It is proprietary and the host (UAssetEditor, see its ADR 0001) supplies its own
//! copy, so this loads `OodleLZ_Decompress` from a DLL on disk and never touches the network:
//! first the file named by `REPAK_OODLE_DLL`, then `oo2core_9_win64.dll` beside the host
//! executable, then by bare name (working folder, `PATH`). The lookup runs once per process and
//! its result, a failed one included, is kept.

use std::ffi::OsString;
use std::os::raw::c_void;
use std::path::PathBuf;
use std::sync::OnceLock;

pub const ENV_VAR: &str = "REPAK_OODLE_DLL";
const DLL_NAME: &str = "oo2core_9_win64.dll";

type OodleLzDecompress = unsafe extern "win64" fn(
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

struct Loaded {
    // Keeps the DLL mapped for as long as `decompress` may be called.
    _library: libloading::Library,
    decompress: OodleLzDecompress,
}

static OODLE: OnceLock<Option<Loaded>> = OnceLock::new();

/// Where to look, in order.
fn candidate_paths(explicit: Option<OsString>, exe: Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = vec![];
    if let Some(explicit) = explicit {
        paths.push(PathBuf::from(explicit));
    }
    if let Some(exe) = exe {
        paths.push(exe.with_file_name(DLL_NAME));
    }
    paths.push(PathBuf::from(DLL_NAME));
    paths
}

fn load_first(paths: &[PathBuf]) -> Option<Loaded> {
    paths.iter().find_map(|path| {
        // SAFETY: loading a library runs its initialisers; the host chose these paths and
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
    })
}

fn cached(
    cell: &OnceLock<Option<Loaded>>,
    load: impl FnOnce() -> Option<Loaded>,
) -> Option<&Loaded> {
    cell.get_or_init(load).as_ref()
}

fn library() -> Option<&'static Loaded> {
    cached(&OODLE, || {
        load_first(&candidate_paths(
            std::env::var_os(ENV_VAR),
            std::env::current_exe().ok(),
        ))
    })
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
        None => Err(format!("{DLL_NAME} not found (set {ENV_VAR} to its path)").into()),
    }
}

/// The getter handed to `PakBuilder::oodle`; fails when no DLL loads.
pub fn getter() -> Result<repak::OodleDecompress, Box<dyn std::error::Error>> {
    require(library())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn candidates_are_the_variable_then_beside_the_exe_then_the_bare_name() {
        let paths = candidate_paths(
            Some("C:/games/oo2core_7_win64.dll".into()),
            Some(PathBuf::from("C:/host/worker.exe")),
        );
        assert_eq!(
            paths,
            [
                PathBuf::from("C:/games/oo2core_7_win64.dll"),
                PathBuf::from("C:/host/oo2core_9_win64.dll"),
                PathBuf::from("oo2core_9_win64.dll"),
            ]
        );
    }

    #[test]
    fn candidates_without_a_variable_or_exe_are_just_the_bare_name() {
        assert_eq!(
            candidate_paths(None, None),
            [PathBuf::from("oo2core_9_win64.dll")]
        );
    }

    #[test]
    fn paths_that_are_not_libraries_load_nothing() {
        let missing = std::env::temp_dir().join("repak_bind_no_such_oo2core_win64.dll");
        let not_a_dll = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(load_first(&[missing, not_a_dll]).is_none());
    }

    #[test]
    fn no_library_is_the_error_the_core_reports_as_a_missing_oodle_pointer() {
        let error = require(None).err().unwrap();
        assert!(error.to_string().contains(ENV_VAR), "{error}");
    }

    #[test]
    fn the_lookup_runs_once_even_when_it_found_nothing() {
        let cell = OnceLock::new();
        let calls = Cell::new(0);
        for _ in 0..3 {
            assert!(cached(&cell, || {
                calls.set(calls.get() + 1);
                None
            })
            .is_none());
        }
        assert_eq!(calls.get(), 1);
    }
}
