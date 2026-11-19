//! The one place where Rust errors and panics become what C can see. Every export runs its body
//! through [`guard`], so a panic (a hostile pak, a bad string) comes back as an error instead of
//! unwinding across `extern "C"`, which aborts the host. The message is also kept per thread for
//! `pak_last_error`, as `errno` is.

use std::any::Any;
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The error is the message a caller gets.
pub type BindResult<T> = Result<T, String>;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// A C string for `text`; a NUL byte inside it is replaced, so this cannot fail.
pub fn to_c_string(text: &str) -> CString {
    CString::new(text.replace('\0', "\u{FFFD}")).expect("every NUL byte was replaced")
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_owned())
}

/// Runs an export's body. A panic becomes `Err`, and any `Err` is remembered for `pak_last_error`.
pub fn guard<T>(body: impl FnOnce() -> BindResult<T>) -> BindResult<T> {
    let result = catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        Err(format!(
            "internal panic: {}",
            panic_message(payload.as_ref())
        ))
    });
    if let Err(message) = &result {
        LAST_ERROR.with(|last| *last.borrow_mut() = Some(to_c_string(message)));
    }
    result
}

/// Takes this thread's last error message, or null if there is none.
pub fn take_last_error() -> *mut c_char {
    LAST_ERROR.with(|last| {
        last.borrow_mut()
            .take()
            .map_or(std::ptr::null_mut(), CString::into_raw)
    })
}

/// The status code of an export that returns one: 0 for success, 1 for failure.
pub fn status(result: &BindResult<()>) -> i32 {
    i32::from(result.is_err())
}

/// Stores `result`'s error in the caller's optional `error_message` out parameter, and null
/// when there is none.
///
/// # Safety
///
/// `error_message` must be null or valid for a write.
pub unsafe fn publish_error<T>(result: &BindResult<T>, error_message: *mut *mut c_char) {
    if error_message.is_null() {
        return;
    }
    *error_message = match result {
        Ok(_) => std::ptr::null_mut(),
        Err(message) => to_c_string(message).into_raw(),
    };
}

/// Takes ownership of a pointer an export consumes.
///
/// # Safety
///
/// `ptr` must be null or come from `Box::into_raw` and not be used again.
pub unsafe fn take_box<T>(ptr: *mut T, what: &str) -> BindResult<Box<T>> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    Ok(Box::from_raw(ptr))
}

/// Borrows a pointer the caller keeps.
///
/// # Safety
///
/// `ptr` must be null or point to a live `T` for the length of the borrow.
pub unsafe fn borrow<'a, T>(ptr: *const T, what: &str) -> BindResult<&'a T> {
    ptr.as_ref().ok_or_else(|| format!("{what} is null"))
}

/// Borrows a pointer the caller keeps, mutably.
///
/// # Safety
///
/// `ptr` must be null or point to a live `T` that nothing else uses during the borrow.
pub unsafe fn borrow_mut<'a, T>(ptr: *mut T, what: &str) -> BindResult<&'a mut T> {
    ptr.as_mut().ok_or_else(|| format!("{what} is null"))
}

/// Reads a NUL-terminated UTF-8 string argument.
///
/// # Safety
///
/// `ptr` must be null or point to a NUL-terminated string.
pub unsafe fn str_arg<'a>(ptr: *const c_char, what: &str) -> BindResult<&'a str> {
    if ptr.is_null() {
        return Err(format!("{what} is null"));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| format!("{what} is not valid UTF-8"))
}

/// Reads a `len`-element array argument; a null pointer is accepted only for length 0.
///
/// # Safety
///
/// `ptr` must be null or valid for reads of `len` elements.
pub unsafe fn slice_arg<'a, T>(ptr: *const T, len: usize, what: &str) -> BindResult<&'a [T]> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(format!("{what} is null but its length is {len}"));
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn last_error() -> Option<String> {
        let ptr = take_last_error();
        // SAFETY: a non-null pointer came from `CString::into_raw` in `guard`.
        (!ptr.is_null()).then(|| {
            unsafe { CString::from_raw(ptr) }
                .to_string_lossy()
                .into_owned()
        })
    }

    #[test]
    fn a_panic_becomes_an_error_and_is_remembered() {
        let result = guard::<()>(|| panic!("boom"));
        assert_eq!(result, Err("internal panic: boom".to_owned()));
        assert_eq!(last_error().as_deref(), Some("internal panic: boom"));
    }

    #[test]
    fn a_formatted_panic_message_is_kept() {
        let result = guard::<()>(|| panic!("entry {}", 7));
        assert_eq!(result, Err("internal panic: entry 7".to_owned()));
    }

    #[test]
    fn an_error_is_remembered_once_and_then_cleared() {
        assert!(guard::<()>(|| Err("bad".to_owned())).is_err());
        assert_eq!(last_error().as_deref(), Some("bad"));
        assert_eq!(last_error(), None);
    }

    #[test]
    fn success_passes_through() {
        assert_eq!(guard(|| Ok(3)), Ok(3));
    }

    #[test]
    fn a_nul_byte_in_a_message_does_not_lose_it() {
        assert_eq!(to_c_string("a\0b").to_str().unwrap(), "a\u{FFFD}b");
    }

    #[test]
    fn a_null_array_with_a_length_is_an_error() {
        // SAFETY: the pointer is null.
        let result = unsafe { slice_arg::<u8>(std::ptr::null(), 4, "data") };
        assert!(result.is_err());
        // SAFETY: as above, and the length is zero.
        assert_eq!(
            unsafe { slice_arg::<u8>(std::ptr::null(), 0, "data") },
            Ok(&[][..])
        );
    }
}
