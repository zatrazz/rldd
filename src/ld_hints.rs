// Run-time link-editor configuration file parsing function.  Although FreeBSD supports
// a ld.so.conf like configuration file (/etc/ld-elf.so.conf), it issues the ldconfig
// withn hard-coded paths from /etc/default/rc.conf.  It is then simpler to parse the
// binary hint file (/var/run/ld-elf.so.hints).

use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};
use std::mem::{size_of, transmute};
use std::path::Path;
use std::str;

use crate::search_path;

#[repr(C)]
struct elfhints_hdr {
    magic: u32,
    version: u32,
    strtab: u32,
    strsize: u32,
    dirlist: u32,
    dirlistlen: u32,
    spare: [u32; 26usize],
}
const ELFHINTS_HDR_LEN: u32 = size_of::<elfhints_hdr>() as u32;

const ELFHINTS_MAGIC: u32 = 0x746e6845;
const ELFHINTS_VERSION: u32 = 0x1;
const ELFHINTS_MAXFILESIZE: u64 = 16 * 1024;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    let mut file = File::open(filename)?;

    if file.metadata()?.len() > ELFHINTS_MAXFILESIZE {
        return Err(Error::new(
            ErrorKind::Other,
            format!("File larger than {}", ELFHINTS_MAXFILESIZE),
        ));
    }

    let hdr: elfhints_hdr = {
        let mut h = [0u8; ELFHINTS_HDR_LEN as usize];
        file.read_exact(&mut h[..])?;
        unsafe { transmute(h) }
    };

    if hdr.magic != ELFHINTS_MAGIC {
        return Err(Error::new(ErrorKind::Other, "Invalid ELFHINTS_MAGIC"));
    }
    if hdr.version != ELFHINTS_VERSION {
        return Err(Error::new(ErrorKind::Other, "Invalid elfhints_hdr version"));
    }

    let mut dirlist: Vec<u8> = vec![0; hdr.dirlistlen as usize];

    let dirlistoff: u64 = (hdr.strtab + hdr.dirlist).into();
    file.seek(SeekFrom::Start(dirlistoff))?;
    file.read_exact(&mut dirlist)?;

    if let Some(dirlist) = str::from_utf8(&dirlist)
        .ok()
        .map(|s| s.trim_matches(char::from(0)).to_string())
    {
        return Ok(search_path::from_string(&dirlist));
    }

    Err(Error::new(
        ErrorKind::Other,
        "Invalid directory list in hint file",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
    }

    fn write_elf_hints(file: &mut File, dirlist: Option<&Vec<&str>>) -> Result<()> {
        let mut dirlistlen = 0u32;
        if let Some(dirlist) = &dirlist {
            dirlistlen = dirlist.iter().fold(0, |len, s| len + s.len() as u32);
            // Add the ':' separator.
            dirlistlen += dirlist.len() as u32 - 1;
        }

        let hdr = elfhints_hdr {
            magic: ELFHINTS_MAGIC,
            version: 1,
            strtab: 0,
            strsize: 0,
            dirlist: ELFHINTS_HDR_LEN,
            dirlistlen: dirlistlen,
            spare: [0; 26usize],
        };

        let hdrbytes = unsafe { any_as_u8_slice(&hdr) };
        file.write_all(hdrbytes)?;
        if let Some(dirlist) = dirlist {
            for dir in dirlist {
                file.write_all(dir.as_bytes())?;
                file.write_all(&[b':'; 1])?;
            }
        }
        file.write_all(&[b'\0'; 1])?;

        Ok(())
    }

    #[test]
    fn parse_ld_so_hints_empty() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");
        File::create(&filepath)?;

        match parse_ld_so_hints(&filepath) {
            Ok(_entries) => Err(Error::new(ErrorKind::Other, "Unexpected entries")),
            Err(_e) => Ok(()),
        }
    }

    #[test]
    fn parse_ld_so_hints_empty_dir() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");
        let mut file = File::create(&filepath)?;

        write_elf_hints(&mut file, None)?;

        match parse_ld_so_hints(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), 0);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_so_hints_one() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");
        let mut file = File::create(&filepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;

        let dirlist = vec![libdir1.to_str().unwrap()];
        write_elf_hints(&mut file, Some(&dirlist))?;

        match parse_ld_so_hints(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), dirlist.len());
                assert_eq!(entries[0], dirlist[0]);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }

    #[test]
    fn parse_ld_so_hints_multiple() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");
        let mut file = File::create(&filepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;
        let libdir3 = tmpdir.path().join("lib3");
        fs::create_dir(&libdir3)?;

        let dirlist = vec![
            libdir1.to_str().unwrap(),
            libdir2.to_str().unwrap(),
            libdir3.to_str().unwrap(),
        ];
        write_elf_hints(&mut file, Some(&dirlist))?;

        match parse_ld_so_hints(&filepath) {
            Ok(entries) => {
                assert_eq!(entries.len(), dirlist.len());
                assert_eq!(entries[0], dirlist[0]);
                assert_eq!(entries[1], dirlist[1]);
                assert_eq!(entries[2], dirlist[2]);
                Ok(())
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }
}
