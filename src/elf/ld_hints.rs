// The parts the FreeBSD and OpenBSD run-time linker hints files have in
// common: a size limit, a fixed header, and a directory list string.

use std::fs::File;
use std::io::{Error, Result};
use std::path::Path;
use std::str;

use crate::{pathutils, search_path};

// Open the FILENAME hints file and read its header, rejecting a file larger
// than MAX_SIZE.  The file is returned positioned after the header, along
// with its size.
pub fn open<P: AsRef<Path>, T: object::Pod + Default>(
    filename: &P,
    max_size: u64,
) -> Result<(File, u64, T)> {
    let mut file = File::open(filename)?;
    let size = file.metadata()?.len();
    if size > max_size {
        return Err(Error::other(format!("File larger than {max_size}")));
    }
    let header = pathutils::read_struct(&mut file)?;
    Ok((file, size, header))
}

// The DIRLIST directory list, trailing NUL included, split on SEPARATORS.
pub fn parse_dirlist(dirlist: &[u8], separators: &[char]) -> Result<search_path::SearchPathVec> {
    match str::from_utf8(dirlist) {
        Ok(dirlist) => Ok(search_path::from_string(
            dirlist.trim_matches(char::from(0)),
            separators,
        )),
        Err(_) => Err(Error::other("Invalid directory list in hint file")),
    }
}
