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

const ELFHINTS_MAGIC: u32 = 0x746e6845;
const ELFHINTS_VERSION: u32 = 0x1;

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<search_path::SearchPathVec> {
    let mut file = File::open(filename)?;

    let hdr: elfhints_hdr = {
        const HLEN: usize = size_of::<elfhints_hdr>();
        let mut h = [0u8; HLEN];
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
