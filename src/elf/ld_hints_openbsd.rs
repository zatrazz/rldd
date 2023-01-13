// Run-time link-editor configuration file parsing function.  OpenBSD version.

use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::path::Path;
use std::str;

use crate::search_path;

// Read a u32 value in native endianess format.
fn read_i64(reader: &mut dyn Read) -> std::io::Result<i64> {
    let mut buffer = [0; 8];
    reader.read(&mut buffer[..])?;
    Ok(i64::from_ne_bytes(buffer) as i64)
}

struct HintsHeader {
    hh_magic: i64,
    hh_version: i64,
    _hh_hashtab: i64,
    _hh_nbucket: i64,
    hh_strtab: i64,
    _hh_strtab_sz: i64,
    hh_ehints: i64,
    hh_dirlist: i64,
}

impl HintsHeader {
    fn from_reader<R: Read>(rdr: &mut R) -> std::io::Result<Self> {
        Ok(HintsHeader {
            hh_magic: read_i64(rdr)?,
            hh_version: read_i64(rdr)?,
            _hh_hashtab: read_i64(rdr)?,
            _hh_nbucket: read_i64(rdr)?,
            hh_strtab: read_i64(rdr)?,
            _hh_strtab_sz: read_i64(rdr)?,
            hh_ehints: read_i64(rdr)?,
            hh_dirlist: read_i64(rdr)?,
        })
    }
}

const HH_MAGIC: i64 = 0o11421044151;
const LD_HINTS_VERSION_2: i64 = 2;
const HINTS_MAXFILESIZE: i64 = i32::MAX as i64;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    let mut file = File::open(filename)?;

    let hsize = file.metadata()?.len() as i64;
    if hsize > HINTS_MAXFILESIZE {
        return Err(Error::new(
            ErrorKind::Other,
            format!("File larger than {}", HINTS_MAXFILESIZE),
        ));
    }

    let hdr = HintsHeader::from_reader(&mut file)?;

    if hdr.hh_magic != HH_MAGIC || hdr.hh_ehints > hsize {
        return Err(Error::new(ErrorKind::Other, "Invalid ELFHINTS_MAGIC"));
    }
    if hdr.hh_version != LD_HINTS_VERSION_2 {
        return Err(Error::new(ErrorKind::Other, "Invalid elfhints_hdr version"));
    }

    let dirlistoff: u64 = (hdr.hh_strtab + hdr.hh_dirlist) as u64;
    file.seek(SeekFrom::Start(dirlistoff))?;

    // OpenBSD header file does not specify the hh_dirlist len, but it encodes it as a
    // C string (with a NULL terminator).
    let mut reader = BufReader::new(file);
    let mut dirlist: Vec<u8> = Vec::<u8>::new();
    reader.read_until(b'\0', &mut dirlist)?;

    if let Some(dirlist) = str::from_utf8(&dirlist)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).to_string())
    {
        return Ok(search_path::from_string(&dirlist, &[':', ';']));
    }

    Err(Error::new(
        ErrorKind::Other,
        "Invalid directory list in hint file",
    ))
}
