// Run-time link-editor configuration file parsing function.  OpenBSD version.

use std::ffi::c_long;
use std::io::{Cursor, Error, Read, Result, Seek};
use std::path::Path;

use object::Pod;

use super::ld_hints;
use crate::{pathutils, search_path};

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

// The number of version numbers of a hash table element.
const MAXDEWEY: usize = 8;

// The link.h hash table element: the string table indexes of a library name
// (without its lib prefix and .so suffix) and path, its version numbers
// (the major and the minor first), and the next element of its bucket.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct hints_bucket {
    hi_namex: i32,
    hi_pathx: i32,
    hi_dewey: [i32; MAXDEWEY],
    hi_ndewey: i32,
    hi_next: i32,
}
// SAFETY: repr(C) integers and integer arrays, without padding (the size is
// the sum of the fields).
unsafe impl Pod for hints_bucket {}
const _: () = assert!(std::mem::size_of::<hints_bucket>() == (4 + MAXDEWEY) * 4);

const HH_MAGIC: i64 = 0o11421044151;
const LD_HINTS_VERSION_2: i64 = 2;
// _dl_maphints rejects a file larger than LONG_MAX.
const HINTS_MAXFILESIZE: u64 = c_long::MAX as u64;

// The hints file: the directories ldconfig scanned, and the hash table of the
// libraries it found there.
#[derive(Debug, Default)]
pub struct Hints {
    pub dirs: search_path::SearchPathVec,
    buckets: Vec<hints_bucket>,
    strtab: Vec<u8>,
}

impl Hints {
    // _dl_findhint: the path of the NAME library of the MAJOR version, with a
    // minor version of at least MINOR, and in the PREFERRED directory when
    // one is given.
    pub fn find(
        &self,
        name: &str,
        major: i32,
        minor: i32,
        preferred: Option<&str>,
    ) -> Option<&str> {
        if self.buckets.is_empty() {
            return None;
        }
        let mut index = hinthash(name, major) as usize % self.buckets.len();
        // A bucket chain can not be longer than the table.
        for _ in 0..self.buckets.len() {
            let bucket = self.buckets.get(index)?;
            // ld.so dies on an index past the string table.
            let entry = self.string(bucket.hi_namex)?;
            let path = self.string(bucket.hi_pathx)?;
            if entry == name
                && bucket.hi_dewey[0] == major
                && (bucket.hi_ndewey < 2 || bucket.hi_dewey[1] >= minor)
            {
                match preferred {
                    None => return Some(path),
                    Some(dir) if path.rfind('/').is_some_and(|end| path[..end] == *dir) => {
                        return Some(path)
                    }
                    _ => {}
                }
            }
            if bucket.hi_next == -1 {
                break;
            }
            index = usize::try_from(bucket.hi_next).ok()?;
        }
        None
    }

    // The NUL terminated string at INDEX of the string table.
    fn string(&self, index: i32) -> Option<&str> {
        let s = self.strtab.get(usize::try_from(index).ok()?..)?;
        let end = s.iter().position(|c| *c == 0)?;
        std::str::from_utf8(&s[..end]).ok()
    }
}

// _dl_hinthash, which leaves the minor version out.
fn hinthash(name: &str, major: i32) -> i32 {
    let mut k: i32 = 0;
    for c in name.bytes() {
        k = (((k << 1) + (k >> 14)) ^ i32::from(c as i8)) & 0x3fff;
    }
    (((k << 1) + (k >> 14)) ^ major.wrapping_mul(257)) & 0x3fff
}

#[cfg(test)]
impl Hints {
    // The hints of the DIRS directory list with the LIBRARIES (name, path,
    // major, and minor, -1 for none).
    pub fn with_libraries(
        dirs: search_path::SearchPathVec,
        libraries: &[(&str, &str, i32, i32)],
    ) -> Hints {
        let mut strtab = Vec::new();
        let buckets = hash_table(&mut strtab, libraries);
        Hints {
            dirs,
            buckets,
            strtab,
        }
    }
}

// The hash table of the LIBRARIES (name, path, major, and minor, -1 for
// none), with their strings appended to STRTAB: each one in its bucket, or
// in the first free one chained to it on a collision, the way ldconfig lays
// them out.
#[cfg(test)]
fn hash_table(strtab: &mut Vec<u8>, libraries: &[(&str, &str, i32, i32)]) -> Vec<hints_bucket> {
    let mut buckets: Vec<Option<hints_bucket>> = vec![None; libraries.len()];
    for (name, path, major, minor) in libraries {
        let mut bucket = hints_bucket {
            hi_namex: strtab.len() as i32,
            hi_next: -1,
            ..Default::default()
        };
        strtab.extend_from_slice(format!("{name}\0").as_bytes());
        bucket.hi_pathx = strtab.len() as i32;
        strtab.extend_from_slice(format!("{path}\0").as_bytes());
        bucket.hi_dewey[0] = *major;
        bucket.hi_dewey[1] = *minor;
        bucket.hi_ndewey = if *minor == -1 { 1 } else { 2 };

        let home = hinthash(name, *major) as usize % buckets.len();
        if buckets[home].is_none() {
            buckets[home] = Some(bucket);
            continue;
        }
        let free = buckets.iter().position(Option::is_none).unwrap();
        buckets[free] = Some(bucket);
        let mut last = home;
        while let Some(next) = buckets[last].filter(|b| b.hi_next != -1) {
            last = next.hi_next as usize;
        }
        buckets[last].as_mut().unwrap().hi_next = free as i32;
    }
    buckets.into_iter().map(Option::unwrap).collect()
}

pub fn parse_ld_so_hints<P: AsRef<Path>>(filename: &P) -> Result<Hints> {
    parse_hints::<_, c_long>(filename)
}

// Parse the hints file with header fields of the LONG type, which the loader
// only reads as its own C long (the tests also use the other size).
fn parse_hints<P: AsRef<Path>, Long: Default + Copy>(filename: &P) -> Result<Hints>
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

    // ld.so maps the whole file.
    let mut data = Vec::new();
    file.rewind()?;
    file.read_to_end(&mut data)?;
    let offset = |value: Long| usize::try_from(i64::from(value)).ok();

    // The loader trusts the offsets, which are checked here to be within the
    // file (without any overflow).
    let dirlistoff = i64::from(hdr.hh_strtab)
        .checked_add(i64::from(hdr.hh_dirlist))
        .and_then(|offset| usize::try_from(offset).ok())
        .filter(|offset| *offset < data.len())
        .ok_or_else(|| Error::other("Invalid directory list offset"))?;

    // OpenBSD header file does not specify the hh_dirlist len, but it encodes it as a
    // C string (with a NULL terminator).
    let dirlist = &data[dirlistoff..];
    let dirlist = match dirlist.iter().position(|c| *c == 0) {
        Some(end) => &dirlist[..end],
        None => dirlist,
    };
    let dirs = ld_hints::parse_dirlist(dirlist, &[':', ';'])?;

    // A string table or hash table out of the file is taken as empty.
    let strtab = offset(hdr.hh_strtab)
        .zip(offset(hdr.hh_strtab_sz))
        .and_then(|(start, size)| data.get(start..start.checked_add(size)?))
        .unwrap_or_default()
        .to_vec();
    let bucket_size = std::mem::size_of::<hints_bucket>();
    let buckets = offset(hdr.hh_hashtab)
        .zip(offset(hdr.hh_nbucket))
        .and_then(|(start, count)| {
            let table = data.get(start..start.checked_add(count.checked_mul(bucket_size)?)?)?;
            table
                .chunks(bucket_size)
                .map(|bucket| pathutils::read_struct(&mut Cursor::new(bucket)).ok())
                .collect::<Option<Vec<_>>>()
        })
        .unwrap_or_default();

    Ok(Hints {
        dirs,
        buckets,
        strtab,
    })
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
        write_adjusted_hints::<Long>(path, dirlist, |_| {})
    }

    // Likewise, with the header fields then changed by ADJUST.
    fn write_adjusted_hints<Long: From<i32>>(
        path: &Path,
        dirlist: &str,
        adjust: impl FnOnce(&mut hints_header<Long>),
    ) -> Result<()>
    where
        hints_header<Long>: Pod,
    {
        write_table::<Long>(path, dirlist, &[], adjust)
    }

    // Write a hints file with the LONG header fields, with DIRLIST at the
    // start of the string table, and a hash table of the LIBRARIES (name,
    // path, major, and minor, -1 for none).
    fn write_table<Long: From<i32>>(
        path: &Path,
        dirlist: &str,
        libraries: &[(&str, &str, i32, i32)],
        adjust: impl FnOnce(&mut hints_header<Long>),
    ) -> Result<()>
    where
        hints_header<Long>: Pod,
    {
        let long = |value: usize| Long::from(value as i32);
        let hdr_size = std::mem::size_of::<hints_header<Long>>();
        let mut strtab = format!("{dirlist}\0").into_bytes();
        let buckets = hash_table(&mut strtab, libraries);
        let table_size = buckets.len() * std::mem::size_of::<hints_bucket>();
        let mut hdr = hints_header {
            hh_magic: Long::from(HH_MAGIC as i32),
            hh_version: Long::from(LD_HINTS_VERSION_2 as i32),
            hh_hashtab: long(hdr_size),
            hh_nbucket: long(buckets.len()),
            hh_strtab: long(hdr_size + table_size),
            hh_strtab_sz: long(strtab.len()),
            hh_ehints: long(hdr_size + table_size + strtab.len()),
            hh_dirlist: long(0),
        };
        adjust(&mut hdr);
        let mut data = object::pod::bytes_of(&hdr).to_vec();
        for bucket in &buckets {
            data.extend_from_slice(object::pod::bytes_of(bucket));
        }
        data.extend_from_slice(&strtab);
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
        let dirs = parse_ld_so_hints(&hints)?.dirs;
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
            parse_hints::<_, i32>(&hints32)?.dirs,
            parse_hints::<_, i64>(&hints64)?.dirs,
        ] {
            assert_eq!(dirs.len(), 2);
            assert_eq!(dirs[0], lib1.as_str());
            assert_eq!(dirs[1], lib2.as_str());
        }
        assert!(parse_hints::<_, i64>(&hints32).is_err());
        assert!(parse_hints::<_, i32>(&hints64).is_err());
        Ok(())
    }

    // A directory list offset that overflows, is negative, or lies past the
    // end of the file is rejected.
    #[test]
    fn reject_bad_dirlist_offset() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let hints = tmpdir.path().join("ld.so.hints");

        let adjusts: [fn(&mut hints_header<i64>); 3] = [
            |hdr| {
                hdr.hh_strtab = i64::MAX;
                hdr.hh_dirlist = 16;
            },
            |hdr| hdr.hh_dirlist = -hdr.hh_strtab - 1,
            |hdr| hdr.hh_dirlist = hdr.hh_strtab_sz,
        ];
        for adjust in adjusts {
            write_adjusted_hints::<i64>(&hints, "/usr/lib", adjust)?;
            assert!(parse_hints::<_, i64>(&hints).is_err());
        }
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

    #[test]
    fn hint_hash() {
        // (('c' << 1) ^ (97 * 257)) & 0x3fff.
        assert_eq!(hinthash("c", 97), 0x21a7);
        assert_eq!(hinthash("", 0), 0);
    }

    // The first library of the bucket chain with the name and major, and a
    // minor high enough, in the directory asked for.
    #[test]
    fn find_hints() -> Result<()> {
        let tmpdir = TempDir::new()?;
        let hints = tmpdir.path().join("ld.so.hints");
        write_table::<c_long>(
            &hints,
            "/usr/lib",
            &[
                ("foo", "/usr/lib/libfoo.so.1.2", 1, 2),
                ("foo", "/usr/local/lib/libfoo.so.1.5", 1, 5),
                ("bar", "/usr/lib/libbar.so.2", 2, -1),
            ],
            |_| {},
        )?;
        let hints = parse_ld_so_hints(&hints)?;
        let find = |name, major, minor, dir| hints.find(name, major, minor, dir);
        assert_eq!(find("foo", 1, 0, None), Some("/usr/lib/libfoo.so.1.2"));
        assert_eq!(
            find("foo", 1, 3, None),
            Some("/usr/local/lib/libfoo.so.1.5")
        );
        assert_eq!(
            find("foo", 1, 0, Some("/usr/local/lib")),
            Some("/usr/local/lib/libfoo.so.1.5")
        );
        assert_eq!(find("foo", 1, 6, None), None);
        assert_eq!(find("foo", 2, 0, None), None);
        assert_eq!(find("foo", 1, 0, Some("/usr")), None);
        // Without a minor version, any one matches.
        assert_eq!(find("bar", 2, 9, None), Some("/usr/lib/libbar.so.2"));
        Ok(())
    }
}
