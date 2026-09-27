// Standard output and error writing.  Unlike print!, which panics on a write
// error, a reader that went away (for instance 'rldd ... | head') ends the
// program quietly with the exit status already due, and any other error is
// reported once.  Unlike eprint!, a failed standard error write is ignored:
// there is nowhere left to report it, and the exit status still tells the
// failure.

use std::io::{ErrorKind, Write};
use std::sync::atomic::{AtomicI32, Ordering};

// The exit status due from the files processed so far.
static EXIT_STATUS: AtomicI32 = AtomicI32::new(0);

pub fn set_exit_status(status: i32) {
    EXIT_STATUS.store(status, Ordering::Relaxed);
}

pub fn exit_status() -> i32 {
    EXIT_STATUS.load(Ordering::Relaxed)
}

pub fn write_stdout(args: std::fmt::Arguments) {
    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_fmt(args) {
        if err.kind() != ErrorKind::BrokenPipe {
            write_stderr(format_args!(
                "{}: error writing to stdout: {err}\n",
                env!("CARGO_PKG_NAME")
            ));
        }
        std::process::exit(write_error_status(&err));
    }
}

// The exit status after the standard output write failed with ERR: the one
// already due when the reader went away, and a failure for any other error.
fn write_error_status(err: &std::io::Error) -> i32 {
    if err.kind() == ErrorKind::BrokenPipe {
        exit_status()
    } else {
        1
    }
}

pub fn write_stderr(args: std::fmt::Arguments) {
    let _ = std::io::stderr().lock().write_fmt(args);
}

macro_rules! out {
    ($($arg:tt)*) => {
        $crate::output::write_stdout(format_args!($($arg)*))
    };
}

macro_rules! outln {
    ($($arg:tt)*) => {
        $crate::output::write_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

macro_rules! errln {
    ($($arg:tt)*) => {
        $crate::output::write_stderr(format_args!("{}\n", format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_pipe_keeps_the_status() {
        let broken = std::io::Error::from(ErrorKind::BrokenPipe);
        assert_eq!(write_error_status(&broken), 0);
        set_exit_status(127);
        assert_eq!(write_error_status(&broken), 127);
        set_exit_status(1);
        assert_eq!(write_error_status(&broken), 1);
        // Any other error is a failure of its own.
        set_exit_status(0);
        assert_eq!(write_error_status(&std::io::Error::other("x")), 1);
    }
}
