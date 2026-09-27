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

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    // The loader does not limit the file size.
    let (mut file, size, hdr) = ld_hints::open::<_, elfhints_hdr>(filename, u64::MAX)?;

    if hdr.magic != ELFHINTS_MAGIC {
        return Err(Error::other("Invalid ELFHINTS_MAGIC"));
    }
    if hdr.version != ELFHINTS_VERSION {
        return Err(Error::other("Invalid elfhints_hdr version"));
    }

    // Like gethints, reject a list whose offsets overflow or which ends past the
    // end of the file before reading it, along with its terminating NUL.
    if hdr.dirlistlen > u32::MAX / 2 {
        return Err(Error::other("Directory list too long"));
    }
    let dirlistoff = hdr
        .strtab
        .checked_add(hdr.dirlist)
        .ok_or_else(|| Error::other("Invalid string table position"))?;
    match dirlistoff.checked_add(hdr.dirlistlen) {
        Some(end) if u64::from(end) <= size => {}
        _ => return Err(Error::other("Truncated hints file")),
    }

    let mut dirlist: Vec<u8> = vec![0; hdr.dirlistlen as usize + 1];
    file.seek(SeekFrom::Start(dirlistoff.into()))?;
    file.read_exact(&mut dirlist)?;
    if dirlist.last() != Some(&0) {
        return Err(Error::other("Directory list not terminated"));
    }

    // Like every rtld search list, split by path_enumerate on both separators.
    ld_hints::parse_dirlist(&dirlist, &[':', ';'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempdir::TempDir;
    use std::fs;
    use std::fs::File;
    use std::io::Write;

    // Write a hints file with the DIRLIST directory list after the header,
    // whose fields ADJUST then changes.
    fn write_hints(
        file: &mut File,
        dirlist: &str,
        adjust: impl FnOnce(&mut elfhints_hdr),
    ) -> Result<()> {
        let mut hdr = elfhints_hdr {
            magic: ELFHINTS_MAGIC,
            version: 1,
            strtab: 0,
            strsize: 0,
            dirlist: std::mem::size_of::<elfhints_hdr>() as u32,
            dirlistlen: dirlist.len() as u32,
            spare: [0; 26usize],
        };
        adjust(&mut hdr);

        file.write_all(object::pod::bytes_of(&hdr))?;
        file.write_all(dirlist.as_bytes())?;
        file.write_all(&[b'\0'; 1])?;

        Ok(())
    }

    fn write_elf_hints(file: &mut File, dirlist: Option<&Vec<&str>>) -> Result<()> {
        let dirlist = dirlist.map_or(String::new(), |dirlist| dirlist.join(":"));
        write_hints(file, &dirlist, |_| {})
    }

    #[test]
    fn parse_ld_so_hints_empty() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");
        File::create(&filepath)?;

        match parse_ld_so_hints(&filepath) {
            Ok(_entries) => Err(Error::other("Unexpected entries")),
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
            Err(e) => Err(Error::other(e)),
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
            Err(e) => Err(Error::other(e)),
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
            Err(e) => Err(Error::other(e)),
        }
    }

    #[test]
    fn parse_ld_so_hints_separators() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");
        let mut file = File::create(&filepath)?;

        let libdir1 = tmpdir.path().join("lib1");
        fs::create_dir(&libdir1)?;
        let libdir2 = tmpdir.path().join("lib2");
        fs::create_dir(&libdir2)?;
        let libdir3 = tmpdir.path().join("lib3");
        fs::create_dir(&libdir3)?;

        let dirlist = [
            libdir1.to_str().unwrap(),
            libdir2.to_str().unwrap(),
            libdir3.to_str().unwrap(),
        ];
        write_hints(
            &mut file,
            &format!("{};{}:{}", dirlist[0], dirlist[1], dirlist[2]),
            |_| {},
        )?;

        let entries = parse_ld_so_hints(&filepath)?;
        assert_eq!(entries.len(), dirlist.len());
        assert_eq!(entries[0], dirlist[0]);
        assert_eq!(entries[1], dirlist[1]);
        assert_eq!(entries[2], dirlist[2]);
        Ok(())
    }

    // A list whose offsets overflow, which ends past the end of the file, or
    // which lacks its terminating NUL is rejected (and not read).
    #[test]
    fn parse_ld_so_hints_bad_dirlist() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let filepath = tmpdir.path().join("ld-elf.so.hints");

        let adjusts: [fn(&mut elfhints_hdr); 6] = [
            |hdr| hdr.strtab = u32::MAX - 0xf,
            |hdr| {
                hdr.strtab = u32::MAX - 0x100;
                hdr.dirlistlen = 0x100;
            },
            |hdr| hdr.dirlistlen = u32::MAX,
            |hdr| hdr.dirlistlen = u32::MAX / 2,
            |hdr| hdr.dirlistlen += 1,
            |hdr| hdr.dirlistlen -= 1,
        ];
        for adjust in adjusts {
            let mut file = File::create(&filepath)?;
            write_hints(&mut file, "/lib:/usr/lib", adjust)?;
            assert!(parse_ld_so_hints(&filepath).is_err());
        }
        Ok(())
    }
}
