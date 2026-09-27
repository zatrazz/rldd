// Run-time link-editor configuration file parsing function.  OpenBSD version.

use std::ffi::c_long;
use std::io::{BufRead, BufReader, Error, Result, Seek, SeekFrom};
use std::path::Path;

use object::Pod;

use super::ld_hints;
use crate::search_path;

// The link.h header, whose fields are C longs: 4 bytes on the ILP32
// architectures (i386, armv7, macppc) and 8 bytes on the LP64 ones.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct hints_header<Long> {
    hh_magic: Long,
    hh_version: Long,
    hh_hashtab: Long,
    hh_nbucket: Long,
    hh_strtab: Long,
    hh_strtab_sz: Long,
    hh_ehints: Long,
    hh_dirlist: Long,
}
// SAFETY: repr(C) with every field of the same integer type, so without
// padding (the size is the sum of the fields).
unsafe impl Pod for hints_header<i32> {}
// SAFETY: as above.
unsafe impl Pod for hints_header<i64> {}
const _: () =
    assert!(std::mem::size_of::<hints_header<c_long>>() == 8 * std::mem::size_of::<c_long>());

const HH_MAGIC: i64 = 0o11421044151;
const LD_HINTS_VERSION_2: i64 = 2;
// _dl_maphints rejects a file larger than LONG_MAX.
const HINTS_MAXFILESIZE: u64 = c_long::MAX as u64;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    parse_hints::<_, c_long>(filename)
}

// Parse the hints file with header fields of the LONG type, which the loader
// only reads as its own C long (the tests also use the other size).
fn parse_hints<P: AsRef<Path>, Long: Default>(filename: &P) -> Result<search_path::SearchPathVec>
where
    hints_header<Long>: Pod,
    i64: From<Long>,
{
    let (mut file, hsize, hdr) =
        ld_hints::open::<_, hints_header<Long>>(filename, HINTS_MAXFILESIZE)?;

    if i64::from(hdr.hh_magic) != HH_MAGIC || i64::from(hdr.hh_ehints) > hsize as i64 {
        return Err(Error::other("Invalid ELFHINTS_MAGIC"));
    }
    if i64::from(hdr.hh_version) != LD_HINTS_VERSION_2 {
        return Err(Error::other("Invalid elfhints_hdr version"));
    }

    let dirlistoff: u64 = (i64::from(hdr.hh_strtab) + i64::from(hdr.hh_dirlist)) as u64;
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

    // Write a hints file with the LONG header fields, without any hash table
    // entry and with DIRLIST at the start of the string table.
    fn write_hints<Long: From<i32>>(path: &Path, dirlist: &str) -> Result<()>
    where
        hints_header<Long>: Pod,
    {
        let long = |value: usize| Long::from(value as i32);
        let hdr_size = std::mem::size_of::<hints_header<Long>>();
        let strtab = format!("{dirlist}\0");
        let hdr = hints_header {
            hh_magic: Long::from(HH_MAGIC as i32),
            hh_version: Long::from(LD_HINTS_VERSION_2 as i32),
            hh_hashtab: long(hdr_size),
            hh_nbucket: long(0),
            hh_strtab: long(hdr_size),
            hh_strtab_sz: long(strtab.len()),
            hh_ehints: long(hdr_size + strtab.len()),
            hh_dirlist: long(0),
        };
        let mut data = object::pod::bytes_of(&hdr).to_vec();
        data.extend_from_slice(strtab.as_bytes());
        fs::write(path, data)
    }

    // Two existing directories below TMPDIR.
    fn lib_dirs(tmpdir: &TempDir) -> Result<(String, String)> {
        let lib1 = tmpdir.path().join("lib1");
        fs::create_dir(&lib1)?;
        let lib2 = tmpdir.path().join("lib2");
        fs::create_dir(&lib2)?;
        Ok((
            lib1.to_str().unwrap().to_string(),
            lib2.to_str().unwrap().to_string(),
        ))
    }

    #[test]
    fn parse_dirlist() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let (lib1, lib2) = lib_dirs(&tmpdir)?;

        let hints = tmpdir.path().join("ld.so.hints");
        write_hints::<c_long>(&hints, &format!("{lib1}:{lib2}"))?;
        let dirs = parse_ld_so_hints(&hints)?;
        assert_eq!(dirs.len(), 2);
        assert_eq!(dirs[0], lib1.as_str());
        assert_eq!(dirs[1], lib2.as_str());
        Ok(())
    }

    // The header of the ILP32 systems has 4 byte fields, and a file of the
    // other word size is rejected.
    #[test]
    fn parse_ilp32_and_lp64_layouts() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let (lib1, lib2) = lib_dirs(&tmpdir)?;
        let dirlist = format!("{lib1};{lib2}");

        let hints32 = tmpdir.path().join("ld.so.hints.32");
        write_hints::<i32>(&hints32, &dirlist)?;
        let hints64 = tmpdir.path().join("ld.so.hints.64");
        write_hints::<i64>(&hints64, &dirlist)?;

        for dirs in [
            parse_hints::<_, i32>(&hints32)?,
            parse_hints::<_, i64>(&hints64)?,
        ] {
            assert_eq!(dirs.len(), 2);
            assert_eq!(dirs[0], lib1.as_str());
            assert_eq!(dirs[1], lib2.as_str());
        }
        assert!(parse_hints::<_, i64>(&hints32).is_err());
        assert!(parse_hints::<_, i32>(&hints64).is_err());
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
