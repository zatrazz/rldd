// A minimal replacement for the `tempfile` crate, covering the only thing the
// tests need: a uniquely named directory that is removed when it goes out of
// scope.

use std::io::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

// Distinguishes directories created within the same process, which the clock
// alone does not do when two tests run back to back.
static COUNTER: AtomicU32 = AtomicU32::new(0);

// The number of names to try before giving up, matching what tempfile does.
const RETRIES: u32 = 16;

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> Result<TempDir> {
        let base = env::temp_dir();
        for _ in 0..RETRIES {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(".tmp-rldd-{}-{seq}-{nanos}", std::process::id()));
            // create_dir fails when the name is taken, so the directory is
            // ours exclusively once this succeeds.
            match fs::create_dir(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::other("could not create a temporary directory"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A test failure should report the assertion, not the cleanup.
        let _ = fs::remove_dir_all(&self.path);
    }
}
