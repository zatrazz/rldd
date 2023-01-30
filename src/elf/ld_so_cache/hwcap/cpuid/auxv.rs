// Read the /proc/self/auxv returning the value for AT_*.

// Code adapted from https://bitbucket.org/marshallpierce/rust-auxv with the changes:
// - Remove usage of byteorder crate, since all usage are done in native endianness.
// - Provide getauxval similar to libc signature.

use std::fs::File;
use std::io::{BufReader, Error, ErrorKind, Read};
use std::path::Path;

#[cfg(target_pointer_width = "32")]
pub type AuxvType = u32;
#[cfg(target_pointer_width = "64")]
pub type AuxvType = u64;

#[allow(dead_code)]
pub const AT_HWCAP: AuxvType = 16;
#[allow(dead_code)]
pub const AT_HWCAP2: AuxvType = 26;

#[derive(Debug, PartialEq)]
pub struct AuxvPair {
    pub key: AuxvType,
    pub value: AuxvType,
}

pub fn getauxval(key: AuxvType) -> Result<AuxvType, std::io::Error> {
    for r in iterate_path(Path::new("/proc/self/auxv"))? {
        let pair = match r {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

        if pair.key == key {
            return Ok(pair.value);
        }
    }
    //Err(ProcfsAuxvError::NotFound)
    Err(Error::new(ErrorKind::Other, "auxv entry not found"))
}

pub struct ProcfsAuxvIter<R: Read> {
    pair_size: usize,
    buf: Vec<u8>,
    input: BufReader<R>,
    keep_going: bool,
}

fn iterate_path(path: &Path) -> Result<ProcfsAuxvIter<File>, std::io::Error> {
    let input = File::open(path).map(BufReader::new)?;

    let pair_size = 2 * std::mem::size_of::<AuxvType>();
    let buf: Vec<u8> = Vec::with_capacity(pair_size);

    Ok(ProcfsAuxvIter::<File> {
        pair_size,
        buf,
        input,
        keep_going: true,
    })
}

impl<R: Read> Iterator for ProcfsAuxvIter<R> {
    type Item = Result<AuxvPair, std::io::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if !self.keep_going {
            return None;
        }
        self.keep_going = false;

        self.buf.clear();
        for _ in 0..self.pair_size {
            self.buf.push(0);
        }

        let mut read_bytes: usize = 0;
        while read_bytes < self.pair_size {
            match self.input.read(&mut self.buf[read_bytes..]) {
                Ok(n) => {
                    if n == 0 {
                        // should not hit EOF before AT_NULL
                        return Some(Err(Error::new(ErrorKind::Other, "invalid auxv format")));
                    }

                    read_bytes += n;
                }
                Err(e) => return Some(Err(e)),
            }
        }

        let mut reader = &self.buf[..];
        let aux_key = read_long(&mut reader).ok()?;
        let aux_val = read_long(&mut reader).ok()?;

        // AT_NULL (0) signals the end of auxv
        if aux_key == 0 {
            return None;
        }

        self.keep_going = true;
        Some(Ok(AuxvPair {
            key: aux_key,
            value: aux_val,
        }))
    }
}

fn read_long(reader: &mut dyn Read) -> std::io::Result<AuxvType> {
    match std::mem::size_of::<AuxvType>() {
        4 => {
            let mut buffer = [0; 4];
            reader.read_exact(&mut buffer[..])?;
            Ok(u32::from_ne_bytes(buffer) as AuxvType)
        }
        8 => {
            let mut buffer = [0; 8];
            reader.read_exact(&mut buffer[..])?;
            Ok(u64::from_ne_bytes(buffer) as AuxvType)
        }
        x => unreachable!("Unexpected type width: {x}"),
    }
}
