use std::path::Path;
use std::{env, fmt, fs, process, str};

use object::elf::*;
use object::read::elf::*;
use object::read::StringTable;
use object::{read, Endianness, Object};

mod ld_conf;
mod search_path;

struct Config {
    ld_so_conf: search_path::SearchPathVec,
    ld_library_path: Vec<String>,
    file: memmap2::Mmap,
}

struct DtNeeded {
    name: String,
}
impl fmt::Display for DtNeeded {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

type DtNeededVec = Vec<DtNeeded>;

fn parse_object(data: &[u8]) -> Result<DtNeededVec, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        Err(_err) => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::Elf32 => parse_elf32(data),
        object::FileKind::Elf64 => parse_elf64(data),
        _ => Err("Invalid object"),
    }
}

fn parse_elf32(_data: &[u8]) -> Result<DtNeededVec, &'static str> {
    Err("Not implemented")
}

fn parse_elf64(data: &[u8]) -> Result<DtNeededVec, &'static str> {
    if let Some(elf) = FileHeader64::<Endianness>::parse(data).handle_err() {
        return parse_elf(elf, data);
    }
    Err("Invalid ELF64 object")
}

fn parse_elf<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
) -> Result<DtNeededVec, &'static str> {
    let kind = match object::FileKind::parse(data) {
        Ok(file) => file,
        _ => return Err("Failed to parse file"),
    };

    match kind {
        object::FileKind::Elf32 => parse_header_elf32(elf, data),
        object::FileKind::Elf64 => parse_header_elf64(elf, data),
        _ => Err("Invalid ELF file"),
    }
}

fn parse_header_elf32<Elf: FileHeader<Endian = Endianness>>(
    _elf: &Elf,
    _data: &[u8],
) -> Result<DtNeededVec, &'static str> {
    Err("Not implemented")
}

trait HandleErr<T> {
    fn handle_err(self) -> Option<T>;
}

impl<T, E: fmt::Display> HandleErr<T> for Result<T, E> {
    fn handle_err(self) -> Option<T> {
        match self {
            Ok(val) => Some(val),
            _ => None,
        }
    }
}

fn parse_header_elf64<Elf: FileHeader<Endian = Endianness>>(
    elf: &Elf,
    data: &[u8],
) -> Result<DtNeededVec, &'static str> {
    let endian = match elf.endian() {
        Ok(val) => val,
        Err(_) => return Err("invalid endianess"),
    };

    match elf.program_headers(endian, data) {
        Ok(segments) => parse_elf_program_headers(endian, data, elf, segments),
        Err(_) => Err("invalid segment"),
    }
}

fn parse_elf_program_headers<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
) -> Result<DtNeededVec, &'static str> {
    match segments
        .iter()
        .find(|&&seg| seg.p_type(endian) == PT_DYNAMIC)
    {
        Some(seg) => parse_elf_segment_dynamic(endian, data, elf, segments, seg),
        None => Err("No dynamic segments found"),
    }
}

fn parse_elf_segment_dynamic<Elf: FileHeader>(
    endian: Elf::Endian,
    data: &[u8],
    elf: &Elf,
    segments: &[Elf::ProgramHeader],
    segment: &Elf::ProgramHeader,
) -> Result<DtNeededVec, &'static str> {
    if let Ok(Some(dynamic)) = segment.dynamic(endian, data) {
        let mut strtab = 0;
        let mut strsz = 0;

        dynamic.iter().for_each(|d| {
            let tag = d.d_tag(endian).into();
            if tag == DT_STRTAB.into() {
                strtab = d.d_val(endian).into();
            } else if tag == DT_STRSZ.into() {
                strsz = d.d_val(endian).into();
            }
        });

        let mut dynstr = StringTable::default();
        // TODO: print error if DT_STRTAB/DT_STRSZ are invalid
        for s in segments {
            if let Ok(Some(data)) = s.data_range(endian, data, strtab, strsz) {
                dynstr = StringTable::new(data, 0, data.len() as u64);
                break;
            }
        }

        return parse_elf_dynamic(endian, elf, dynamic, dynstr);
    }
    Err("Failure to parse dynamic segment")
}

fn parse_elf_dynamic<Elf: FileHeader>(
    endian: Elf::Endian,
    _elf: &Elf,
    dynamic: &[Elf::Dyn],
    dynstr: StringTable,
) -> Result<DtNeededVec, &'static str> {
    let mut dtneeded = DtNeededVec::new();
    for d in dynamic {
        if d.d_tag(endian).into() == DT_NULL.into() {
            break;
        }

        if d.tag32(endian).is_none() || !d.is_string(endian) {
            continue;
        }

        match d.string(endian, dynstr) {
            Err(_) => continue,
            Ok(s) => {
                if let Ok(s) = str::from_utf8(s) {
                    dtneeded.push(DtNeeded {
                        name: s.to_string(),
                    });
                }
            }
        }
    }
    Ok(dtneeded)
}

fn parse_ld_library_path() -> Vec<String> {
    let mut r = Vec::new();

    let ld_library_path = match env::var("LD_LIBRARY_PATH") {
        Ok(path) => path,
        Err(_) => "".to_string(),
    };

    for path in ld_library_path.split(":") {
        r.push(path.to_string());
    }

    r
}

fn print_dependencies(config: &Config) {
    let dtneeded = parse_object(&*config.file);
    if dtneeded.is_ok() {
        for entry in dtneeded.unwrap() {
            println!("{}", entry);
        }
    } else {
        println!("Problem opening the file: {:?}", dtneeded.err());
    }
}

fn main() {
    let mut args = env::args();
    let cmd = args.next().unwrap();
    if args.len() == 0 {
        eprintln!("Usage {} file", cmd);
        process::exit(1);
    }
    let filename = args.next().unwrap();

    let file = match fs::File::open(&filename) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open file '{}': {}", filename, err,);
            process::exit(1);
        }
    };

    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            eprintln!("Failed to map file '{}': {}", filename, err,);
            process::exit(1);
        }
    };

    let object = match read::File::parse(&*file) {
        Ok(object) => object,
        Err(err) => {
            eprintln!("Failed to read file '{}': {}", filename, err,);
            process::exit(1);
        }
    };

    let ld_so_conf =
        match ld_conf::parse_ld_so_conf(object.architecture(), &Path::new("/etc/ld.so.conf")) {
            Ok(ld_so_conf) => ld_so_conf,
            Err(err) => {
                eprintln!("Failed to read loader cache config: {}", err,);
                process::exit(1);
            }
        };
    let ld_library_path = parse_ld_library_path();

    let config = Config {
        ld_so_conf: ld_so_conf,
        ld_library_path: ld_library_path,
        file: file,
    };

    print_dependencies(&config)
}
