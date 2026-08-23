// The API set schema namespace, held on the '.apiset' section of apisetschema.dll.
// This redirects the 'api-ms-*' and 'ext-ms-*' virtual dependencies to the module
// that really implements them.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use object::read::pe::{PeFile32, PeFile64};
use object::{FileKind, Object, ObjectSection};

// The Windows 10 and later namespace layout.
const NAMESPACE_V6: u32 = 6;
const HEADER_SIZE: usize = 28;
const ENTRY_SIZE: usize = 24;
const VALUE_SIZE: usize = 20;

#[derive(Debug)]
struct ApiSetValue {
    // The importing module this value applies to, empty for the default one.
    alias: String,
    host: String,
}

#[derive(Default, Debug)]
pub struct ApiSetMap {
    entries: HashMap<String, Vec<ApiSetValue>>,
    version: u32,
}

impl ApiSetMap {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    // Resolve NAME to the module that implements it, following the alias of
    // the IMPORTING module.  Returns None when NAME is not an api set, and an
    // empty host when the set implements nothing on this system.
    pub fn resolve(&self, name: &str, importing: &str) -> Option<&str> {
        if !is_apiset(name) {
            return None;
        }
        let values = self.entries.get(&key(name))?;
        values
            .iter()
            .find(|value| !value.alias.is_empty() && value.alias.eq_ignore_ascii_case(importing))
            .or_else(|| values.first())
            .map(|value| value.host.as_str())
    }
}

// The loader only checks the first four characters ('api-'/'ext-'), not the
// full 'api-ms-win-' prefix.  Geoff Chappell, 'Windows API Sets', documents
// the 'API-' prefix and the 'EXT-' one added by Windows 8:
// https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm
// Wine implements the same check in get_apiset_entry, dlls/ntdll/loader.c:
//   if (len <= 4) return STATUS_INVALID_PARAMETER;
//   if (wcsnicmp( name, L"api-", 4 ) && wcsnicmp( name, L"ext-", 4 ))
//       return STATUS_INVALID_PARAMETER;
pub fn is_apiset(name: &str) -> bool {
    name.len() > 4
        && (name[..4].eq_ignore_ascii_case("api-") || name[..4].eq_ignore_ascii_case("ext-"))
}

// The namespace is indexed without the '.dll' suffix and without the trailing
// version field, the way the loader hashes the name. The get_apiset_entry stops at
// the first '.', hashes up to the last '-' before it, and folds the name to
// lower case as it goes.
fn key(name: &str) -> String {
    let name = name
        .strip_suffix(".dll")
        .or_else(|| name.strip_suffix(".DLL"))
        .unwrap_or(name);
    let name = match name.rfind('-') {
        Some(idx) => &name[..idx],
        None => name,
    };
    name.to_lowercase()
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

// The names are UTF-16LE with the length in bytes.
fn utf16_at(data: &[u8], offset: u32, len: u32) -> Option<String> {
    let start = offset as usize;
    let bytes = data.get(start..start.checked_add(len as usize)?)?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

pub fn parse(data: &[u8]) -> ApiSetMap {
    let mut map = ApiSetMap::default();
    let (Some(version), Some(count), Some(entry_offset)) =
        (u32_at(data, 0), u32_at(data, 12), u32_at(data, 16))
    else {
        return map;
    };
    map.version = version;
    if version != NAMESPACE_V6
        || (data.len() as u32) < entry_offset
        || entry_offset < HEADER_SIZE as u32
    {
        return map;
    }

    for i in 0..count as usize {
        let Some(entry) = (entry_offset as usize).checked_add(i * ENTRY_SIZE) else {
            break;
        };
        let (Some(name_offset), Some(name_length), Some(value_offset), Some(value_count)) = (
            u32_at(data, entry + 4),
            u32_at(data, entry + 8),
            u32_at(data, entry + 16),
            u32_at(data, entry + 20),
        ) else {
            continue;
        };
        let Some(name) = utf16_at(data, name_offset, name_length) else {
            continue;
        };

        let mut values = Vec::with_capacity(value_count as usize);
        for j in 0..value_count as usize {
            let value = value_offset as usize + j * VALUE_SIZE;
            let (Some(ao), Some(al), Some(ho), Some(hl)) = (
                u32_at(data, value + 4),
                u32_at(data, value + 8),
                u32_at(data, value + 12),
                u32_at(data, value + 16),
            ) else {
                continue;
            };
            let (Some(alias), Some(host)) = (utf16_at(data, ao, al), utf16_at(data, ho, hl)) else {
                continue;
            };
            values.push(ApiSetValue { alias, host });
        }
        map.entries.insert(key(&name), values);
    }
    map
}

fn read_section<P: AsRef<Path>>(filename: P) -> Option<Vec<u8>> {
    let file = fs::File::open(filename).ok()?;
    let mmap = unsafe { memmap2::Mmap::map(&file) }.ok()?;
    let data: &[u8] = &mmap;
    match FileKind::parse(data).ok()? {
        FileKind::Pe32 => Some(
            PeFile32::parse(data)
                .ok()?
                .section_by_name(".apiset")?
                .data()
                .ok()?
                .to_vec(),
        ),
        FileKind::Pe64 => Some(
            PeFile64::parse(data)
                .ok()?
                .section_by_name(".apiset")?
                .data()
                .ok()?
                .to_vec(),
        ),
        _ => None,
    }
}

pub fn load(system_dir: &str) -> ApiSetMap {
    match read_section(Path::new(system_dir).join("apisetschema.dll")) {
        Some(data) => parse(&data),
        None => ApiSetMap::default(),
    }
}
