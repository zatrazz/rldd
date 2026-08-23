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

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_str(data: &mut Vec<u8>, string: &str) -> (u32, u32) {
        let offset = data.len() as u32;
        let units: Vec<u16> = string.encode_utf16().collect();
        for unit in &units {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        (offset, (units.len() * 2) as u32)
    }

    // A namespace holding a single set with a default host and an alias for
    // one importing module.
    fn namespace(version: u32) -> Vec<u8> {
        let entry = HEADER_SIZE;
        let value = entry + ENTRY_SIZE;
        let mut data = vec![0u8; value + 2 * VALUE_SIZE];

        let (name_o, name_l) = put_str(&mut data, "api-ms-win-test-l1-1-0");
        let (host_o, host_l) = put_str(&mut data, "testhost.dll");
        let (alias_o, alias_l) = put_str(&mut data, "caller.dll");
        let (ahost_o, ahost_l) = put_str(&mut data, "aliashost.dll");

        put_u32(&mut data, 0, version);
        put_u32(&mut data, 12, 1);
        put_u32(&mut data, 16, entry as u32);

        put_u32(&mut data, entry + 4, name_o);
        put_u32(&mut data, entry + 8, name_l);
        put_u32(&mut data, entry + 16, value as u32);
        put_u32(&mut data, entry + 20, 2);

        // The default value carries no alias.
        put_u32(&mut data, value + 12, host_o);
        put_u32(&mut data, value + 16, host_l);

        put_u32(&mut data, value + VALUE_SIZE + 4, alias_o);
        put_u32(&mut data, value + VALUE_SIZE + 8, alias_l);
        put_u32(&mut data, value + VALUE_SIZE + 12, ahost_o);
        put_u32(&mut data, value + VALUE_SIZE + 16, ahost_l);

        data
    }

    #[test]
    fn resolve_default_host() {
        let map = parse(&namespace(NAMESPACE_V6));
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.resolve("api-ms-win-test-l1-1-0.dll", "other.dll"),
            Some("testhost.dll")
        );
    }

    // The alias of the importing module wins over the default host, and the
    // module names are compared without regard to case.
    #[test]
    fn resolve_importing_alias() {
        let map = parse(&namespace(NAMESPACE_V6));
        assert_eq!(
            map.resolve("api-ms-win-test-l1-1-0.dll", "CALLER.DLL"),
            Some("aliashost.dll")
        );
    }

    // The namespace is indexed without the trailing version field, so a set
    // built against another revision still resolves.
    #[test]
    fn resolve_other_revision() {
        let map = parse(&namespace(NAMESPACE_V6));
        assert_eq!(
            map.resolve("api-ms-win-test-l1-1-3.dll", "other.dll"),
            Some("testhost.dll")
        );
    }

    #[test]
    fn resolve_non_apiset() {
        let map = parse(&namespace(NAMESPACE_V6));
        assert_eq!(map.resolve("kernel32.dll", "other.dll"), None);
        assert_eq!(
            map.resolve("api-ms-win-other-l1-1-0.dll", "other.dll"),
            None
        );
    }

    // Only the version 6 layout is parsed.
    #[test]
    fn unsupported_version() {
        let map = parse(&namespace(4));
        assert_eq!(map.version(), 4);
        assert!(map.is_empty());
    }

    #[test]
    fn apiset_names() {
        assert!(is_apiset("api-ms-win-core-x-l1-1-0.dll"));
        assert!(is_apiset("EXT-MS-Win-x-l1-1-0.dll"));
        assert!(!is_apiset("kernel32.dll"));
        assert!(!is_apiset("api-"));
    }

    #[test]
    fn namespace_key() {
        assert_eq!(key("API-MS-Win-Test-L1-1-0.dll"), "api-ms-win-test-l1-1");
        assert_eq!(key("noversion"), "noversion");
    }
}
