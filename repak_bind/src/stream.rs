//! A `Read + Write + Seek` over the host's stream callbacks. The host is untrusted: a negative
//! result is a failure, and a count larger than the buffer is an error rather than something to
//! index with.

use std::ffi::c_void;
use std::io::{self, Read, Seek, SeekFrom, Write};

/// The host's stream. A null callback is reported as an error when it is used.
#[repr(C)]
pub struct StreamCallbacks {
    pub context: *mut c_void,
    pub read: Option<extern "C" fn(*mut c_void, *mut u8, usize) -> isize>,
    pub write: Option<extern "C" fn(*mut c_void, *const u8, usize) -> isize>,
    pub seek: Option<extern "C" fn(*mut c_void, i64, i32) -> i64>,
    pub flush: Option<extern "C" fn(*mut c_void) -> i32>,
}

pub struct Stream {
    callbacks: StreamCallbacks,
}

impl Stream {
    pub fn new(callbacks: StreamCallbacks) -> Self {
        Stream { callbacks }
    }
}

fn missing(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("the {name} stream callback is null"),
    )
}

/// The byte count a read or write callback reported, if it is possible for a buffer of `requested`.
fn byte_count(name: &str, result: isize, requested: usize) -> io::Result<usize> {
    match usize::try_from(result) {
        Ok(count) if count <= requested => Ok(count),
        Ok(count) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the {name} stream callback reported {count} bytes for a {requested} byte buffer"
            ),
        )),
        Err(_) => Err(io::Error::other(format!(
            "the {name} stream callback failed with {result}"
        ))),
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.callbacks.read.ok_or_else(|| missing("read"))?;
        byte_count(
            "read",
            read(self.callbacks.context, buf.as_mut_ptr(), buf.len()),
            buf.len(),
        )
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let write = self.callbacks.write.ok_or_else(|| missing("write"))?;
        byte_count(
            "write",
            write(self.callbacks.context, buf.as_ptr(), buf.len()),
            buf.len(),
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        let flush = self.callbacks.flush.ok_or_else(|| missing("flush"))?;
        match flush(self.callbacks.context) {
            result if result < 0 => Err(io::Error::other(format!(
                "the flush stream callback failed with {result}"
            ))),
            _ => Ok(()),
        }
    }
}

impl Seek for Stream {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let seek = self.callbacks.seek.ok_or_else(|| missing("seek"))?;
        let (offset, whence) = match pos {
            SeekFrom::Start(offset) => (
                i64::try_from(offset).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek offset is out of range")
                })?,
                0,
            ),
            SeekFrom::End(offset) => (offset, 2),
            SeekFrom::Current(offset) => (offset, 1),
        };
        let result = seek(self.callbacks.context, offset, whence);
        u64::try_from(result)
            .map_err(|_| io::Error::other(format!("the seek stream callback failed with {result}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn reports_more_than_asked(_: *mut c_void, _: *const u8, len: usize) -> isize {
        len as isize + 1
    }

    extern "C" fn fails(_: *mut c_void, _: *const u8, _: usize) -> isize {
        -1
    }

    fn writing_with(write: extern "C" fn(*mut c_void, *const u8, usize) -> isize) -> Stream {
        Stream::new(StreamCallbacks {
            context: std::ptr::null_mut(),
            read: None,
            write: Some(write),
            seek: None,
            flush: None,
        })
    }

    #[test]
    fn a_write_count_larger_than_the_buffer_is_an_error() {
        let error = writing_with(reports_more_than_asked)
            .write(b"abc")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_negative_write_result_is_an_error() {
        assert!(writing_with(fails).write(b"abc").is_err());
    }

    #[test]
    fn write_all_does_not_index_past_the_buffer() {
        // std's write_all slices the buffer by the returned count, which would panic.
        assert!(writing_with(reports_more_than_asked)
            .write_all(b"abc")
            .is_err());
    }

    #[test]
    fn a_null_callback_is_an_error_not_a_call() {
        let mut stream = writing_with(fails);
        assert!(stream.read(&mut [0u8; 4]).is_err());
        assert!(stream.seek(SeekFrom::Start(0)).is_err());
        assert!(stream.flush().is_err());
    }
}
