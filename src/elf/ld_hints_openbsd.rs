// Run-time link-editor configuration file parsing function.  OpenBSD version.

use std::io::{BufRead, BufReader, Error, Result, Seek, SeekFrom};
use std::path::Path;

use object::Pod;

use super::ld_hints;
use crate::search_path;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct hints_header {
    hh_magic: i64,
    hh_version: i64,
    hh_hashtab: i64,
    hh_nbucket: i64,
    hh_strtab: i64,
    hh_strtab_sz: i64,
    hh_ehints: i64,
    hh_dirlist: i64,
}
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for hints_header {}
const _: () = assert!(std::mem::size_of::<hints_header>() == 8 * 8);

const HH_MAGIC: i64 = 0o11421044151;
const LD_HINTS_VERSION_2: i64 = 2;
const HINTS_MAXFILESIZE: u64 = i32::MAX as u64;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    let (mut file, hsize, hdr) = ld_hints::open::<_, hints_header>(filename, HINTS_MAXFILESIZE)?;

    if hdr.hh_magic != HH_MAGIC || hdr.hh_ehints > hsize as i64 {
        return Err(Error::other("Invalid ELFHINTS_MAGIC"));
    }
    if hdr.hh_version != LD_HINTS_VERSION_2 {
        return Err(Error::other("Invalid elfhints_hdr version"));
    }

    let dirlistoff: u64 = (hdr.hh_strtab + hdr.hh_dirlist) as u64;
    file.seek(SeekFrom::Start(dirlistoff))?;

    // OpenBSD header file does not specify the hh_dirlist len, but it encodes it as a
    // C string (with a NULL terminator).
    let mut reader = BufReader::new(file);
    let mut dirlist: Vec<u8> = Vec::<u8>::new();
    reader.read_until(b'\0', &mut dirlist)?;

    ld_hints::parse_dirlist(&dirlist, &[':', ';'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use std::fs;

    // Write a hints file without any hash table entry, with DIRLIST as the
    // directory list at the start of the string table.
    fn write_hints(path: &Path, dirlist: &str) -> Result<()> {
        let hdr_size = std::mem::size_of::<hints_header>() as i64;
        let strtab = format!("{dirlist}\0");
        let hdr = hints_header {
            hh_magic: HH_MAGIC,
            hh_version: LD_HINTS_VERSION_2,
            hh_hashtab: hdr_size,
            hh_nbucket: 0,
            hh_strtab: hdr_size,
            hh_strtab_sz: strtab.len() as i64,
            hh_ehints: hdr_size + strtab.len() as i64,
            hh_dirlist: 0,
        };
        let mut data = object::pod::bytes_of(&hdr).to_vec();
        data.extend_from_slice(strtab.as_bytes());
        fs::write(path, data)
    }

    #[test]
    fn parse_dirlist() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let lib1 = tmpdir.path().join("lib1");
        fs::create_dir(&lib1)?;
        let lib2 = tmpdir.path().join("lib2");
        fs::create_dir(&lib2)?;
        let (lib1, lib2) = (lib1.to_str().unwrap(), lib2.to_str().unwrap());

        let hints = tmpdir.path().join("ld.so.hints");
        write_hints(&hints, &format!("{lib1}:{lib2}"))?;
        let dirs = parse_ld_so_hints(&hints)?;
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0], lib1);
        assert_eq!(dirs[1], lib2);
        Ok(())
    }

    #[test]
    fn reject_empty_file() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let hints = tmpdir.path().join("ld.so.hints");
        fs::write(&hints, [])?;
        assert!(parse_ld_so_hints(&hints).is_err());
        Ok(())
    }
}
