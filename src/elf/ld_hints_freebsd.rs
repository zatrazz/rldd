// Run-time link-editor configuration file parsing function.  Although FreeBSD supports
// a ld.so.conf like configuration file (/etc/ld-elf.so.conf), it issues the ldconfig
// withn hard-coded paths from /etc/default/rc.conf.  It is then simpler to parse the
// binary hint file (/var/run/ld-elf.so.hints).

use std::io::{Error, Read, Result, Seek, SeekFrom};
use std::path::Path;

use object::Pod;

use super::ld_hints;
use crate::search_path;

#[derive(Clone, Copy, Debug, Default)]
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
// SAFETY: repr(C) integers and byte arrays, without padding (the size is the
// sum of the fields).
unsafe impl Pod for elfhints_hdr {}
const _: () = assert!(std::mem::size_of::<elfhints_hdr>() == (6 + 26) * 4);

const ELFHINTS_MAGIC: u32 = 0x746e6845;
const ELFHINTS_VERSION: u32 = 0x1;
const ELFHINTS_MAXFILESIZE: u64 = 16 * 1024;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    let (mut file, _, hdr) = ld_hints::open::<_, elfhints_hdr>(filename, ELFHINTS_MAXFILESIZE)?;

    if hdr.magic != ELFHINTS_MAGIC {
        return Err(Error::other("Invalid ELFHINTS_MAGIC"));
    }
    if hdr.version != ELFHINTS_VERSION {
        return Err(Error::other("Invalid elfhints_hdr version"));
    }

    let mut dirlist: Vec<u8> = vec![0; hdr.dirlistlen as usize];

    let dirlistoff: u64 = (hdr.strtab + hdr.dirlist).into();
    file.seek(SeekFrom::Start(dirlistoff))?;
    file.read_exact(&mut dirlist)?;

    ld_hints::parse_dirlist(&dirlist, &[':'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use std::fs;
    use std::fs::File;
    use std::io::ErrorKind;
    use std::io::Write;

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
            dirlist: std::mem::size_of::<elfhints_hdr>() as u32,
            dirlistlen: dirlistlen,
            spare: [0; 26usize],
        };

        file.write_all(object::pod::bytes_of(&hdr))?;
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
