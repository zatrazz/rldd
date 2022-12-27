// Read the /proc/self/auxv returning the value for AT_*.

// Code adapted from https://bitbucket.org/marshallpierce/rust-auxv with the changes:
// - Remove usage of byteorder crate, since all usage are done in native endianness.
// - Provide getauxval similar to libc signature.

use std::fs::File;
use std::io::{BufReader, Read};
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

#[derive(Debug)]
pub enum ProcfsAuxvError {
    IoError,
    InvalidFormat,
    NotFound,
}

pub fn getauxval(key: AuxvType) -> Result<AuxvType, ProcfsAuxvError> {
    for r in iterate_path(&Path::new("/proc/self/auxv"))? {
        let pair = match r {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

        if pair.key == key {
            return Ok(pair.value);
        }
    }
    Err(ProcfsAuxvError::NotFound)
}

pub struct ProcfsAuxvIter<R: Read> {
    pair_size: usize,
    buf: Vec<u8>,
    input: BufReader<R>,
    keep_going: bool,
}

fn iterate_path(path: &Path) -> Result<ProcfsAuxvIter<File>, ProcfsAuxvError> {
    let input = File::open(path)
        .map_err(|_| ProcfsAuxvError::IoError)
        .map(|f| BufReader::new(f))?;

    let pair_size = 2 * std::mem::size_of::<AuxvType>();
    let buf: Vec<u8> = Vec::with_capacity(pair_size);

    Ok(ProcfsAuxvIter::<File> {
        pair_size: pair_size,
        buf: buf,
        input: input,
        keep_going: true,
    })
}

impl<R: Read> Iterator for ProcfsAuxvIter<R> {
    type Item = Result<AuxvPair, ProcfsAuxvError>;
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
                        return Some(Err(ProcfsAuxvError::InvalidFormat));
                    }

                    read_bytes += n;
                }
                Err(_) => return Some(Err(ProcfsAuxvError::IoError)),
            }
        }

        let mut reader = &self.buf[..];
        let aux_key = match read_long(&mut reader) {
            Ok(x) => x,
            Err(_) => return Some(Err(ProcfsAuxvError::InvalidFormat)),
        };
        let aux_val = match read_long(&mut reader) {
            Ok(x) => x,
            Err(_) => return Some(Err(ProcfsAuxvError::InvalidFormat)),
        };

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
            reader.read(&mut buffer[..]).unwrap();
            Ok(u32::from_ne_bytes(buffer) as AuxvType)
        }
        8 => {
            let mut buffer = [0; 8];
            reader.read(&mut buffer[..]).unwrap();
            Ok(u64::from_ne_bytes(buffer) as AuxvType)
        }
        x => panic!("Unexpected type width: {}", x),
    }
}
