// Standard output writing.  Unlike print!, which panics on a write error, a
// reader that went away (for instance 'rldd ... | head') ends the program
// quietly, and any other error is reported once.

use std::io::{ErrorKind, Write};

pub fn write_stdout(args: std::fmt::Arguments) {
    let mut stdout = std::io::stdout().lock();
    if let Err(err) = stdout.write_fmt(args) {
        if err.kind() == ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
        eprintln!("{}: error writing to stdout: {err}", env!("CARGO_PKG_NAME"));
        std::process::exit(1);
    }
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
