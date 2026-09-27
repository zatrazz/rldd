// The API set schema namespace, held on the '.apiset' section of apisetschema.dll
// along with the extensions the ApiSetSchemaExtensions key registers.  This
// redirects the 'api-ms-*' and 'ext-ms-*' virtual dependencies to the module that
// really implements them.

use std::collections::HashMap;
use std::path::Path;

use object::{FileKind, Object, ObjectSection};

// The Windows 10 and later namespace layout.
const NAMESPACE_V6: u32 = 6;
const HEADER_SIZE: usize = 28;
const ENTRY_SIZE: usize = 24;
const VALUE_SIZE: usize = 20;

// The entry flag of the sets an extension does not provide.
const ENTRY_SEALED: u32 = 1;

// The layout of the '.apiset' section of the schema extensions, as found on
// Windows 11 24H2 (the files are undocumented): a 20 bytes header with the
// version 7, the size, the flags, the offset of the entries and, on its last
// two bytes, their count; 20 bytes entries with the offset of the ASCII set
// name, the offset of its values, and the name length in bytes and the value
// count on two bytes each; and 16 bytes values with the offset of the UTF-16
// host and of the importing module alias, and their lengths in characters.
// No extension there has an alias, so its place is the one the base layout
// suggests.
const EXTENSION_VERSION: u16 = 7;
const EXTENSION_HEADER_SIZE: usize = 20;
const EXTENSION_ENTRY_SIZE: usize = 20;
const EXTENSION_VALUE_SIZE: usize = 16;

const EXTENSIONS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Session Manager\ApiSetSchemaExtensions";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApiSetValue {
    // The importing module this value applies to, empty for the default one.
    alias: String,
    host: String,
}

#[derive(Debug)]
struct ApiSetEntry {
    sealed: bool,
    values: Vec<ApiSetValue>,
}

#[derive(Default, Debug)]
pub struct ApiSetMap {
    entries: HashMap<String, ApiSetEntry>,
    version: u32,
    // The number of extensions merged.
    extensions: usize,
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

    pub fn extensions(&self) -> usize {
        self.extensions
    }

    // Take the hosts an EXTENSION provides.  The base schema declares every
    // set, and an extension only provides the values of the ones it leaves
    // unsealed: on Windows 11 24H2 the namespace the kernel maps in every
    // process (the PEB ApiSetMap) is the base one with the values of the
    // unsealed sets the extensions name replaced by theirs (the Hyper-V ones,
    // empty on the base schema), the sealed ones as they are, and no set
    // added.
    fn merge(&mut self, extension: Vec<(String, Vec<ApiSetValue>)>) {
        for (name, values) in extension {
            match self.entries.get_mut(&key(&name)) {
                Some(entry) if !entry.sealed => entry.values = values,
                _ => {}
            }
        }
        self.extensions += 1;
    }

    // Resolve NAME to the module that implements it, following the alias of
    // the IMPORTING module.  Returns None when NAME is not an api set, and an
    // empty host when the set implements nothing on this system.
    pub fn resolve(&self, name: &str, importing: &str) -> Option<&str> {
        if !is_apiset(name) {
            return None;
        }
        let values = &self.entries.get(&key(name))?.values;
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
// The prefix is compared as bytes, since the name may hold a character that
// spans the fourth byte.
pub fn is_apiset(name: &str) -> bool {
    let name = name.as_bytes();
    name.len() > 4
        && (name[..4].eq_ignore_ascii_case(b"api-") || name[..4].eq_ignore_ascii_case(b"ext-"))
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

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
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
        let (
            Some(flags),
            Some(name_offset),
            Some(name_length),
            Some(value_offset),
            Some(value_count),
        ) = (
            u32_at(data, entry),
            u32_at(data, entry + 4),
            u32_at(data, entry + 8),
            u32_at(data, entry + 16),
            u32_at(data, entry + 20),
        )
        else {
            continue;
        };
        let Some(name) = utf16_at(data, name_offset, name_length) else {
            continue;
        };

        let mut values = Vec::new();
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
        let entry = ApiSetEntry {
            sealed: flags & ENTRY_SEALED != 0,
            values,
        };
        map.entries.insert(key(&name), entry);
    }
    map
}

// The sets of a schema extension, with their values.
fn parse_extension(data: &[u8]) -> Vec<(String, Vec<ApiSetValue>)> {
    let mut sets = Vec::new();
    let (Some(version), Some(entry_offset), Some(count)) =
        (u16_at(data, 0), u32_at(data, 12), u16_at(data, 18))
    else {
        return sets;
    };
    if version != EXTENSION_VERSION || (entry_offset as usize) < EXTENSION_HEADER_SIZE {
        return sets;
    }
    for i in 0..usize::from(count) {
        let entry = entry_offset as usize + i * EXTENSION_ENTRY_SIZE;
        let (Some(name_offset), Some(value_offset), Some(name_length), Some(value_count)) = (
            u32_at(data, entry),
            u32_at(data, entry + 4),
            u16_at(data, entry + 8),
            u16_at(data, entry + 10),
        ) else {
            continue;
        };
        let start = name_offset as usize;
        let Some(name) = data.get(start..start + usize::from(name_length)) else {
            continue;
        };
        let mut values = Vec::new();
        for j in 0..usize::from(value_count) {
            let value = value_offset as usize + j * EXTENSION_VALUE_SIZE;
            let (Some(ho), Some(ao), Some(hl), Some(al)) = (
                u32_at(data, value),
                u32_at(data, value + 4),
                u32_at(data, value + 8),
                u32_at(data, value + 12),
            ) else {
                continue;
            };
            let chars = |len: u32| len.checked_mul(2);
            let (Some(host), Some(alias)) = (
                chars(hl).and_then(|len| utf16_at(data, ho, len)),
                chars(al).and_then(|len| utf16_at(data, ao, len)),
            ) else {
                continue;
            };
            values.push(ApiSetValue { alias, host });
        }
        sets.push((String::from_utf8_lossy(name).into_owned(), values));
    }
    sets
}

fn read_section<P: AsRef<Path>>(filename: P) -> Option<Vec<u8>> {
    let mmap = crate::pathutils::map_file(&filename).ok()?;
    let data: &[u8] = &mmap;
    if !matches!(FileKind::parse(data).ok()?, FileKind::Pe32 | FileKind::Pe64) {
        return None;
    }
    let file = object::File::parse(data).ok()?;
    Some(file.section_by_name(".apiset")?.data().ok()?.to_vec())
}

// The base schema along with the extensions, which the kernel merges at boot
// from the files each subkey of the ApiSetSchemaExtensions key names on the
// system directory.
pub fn load(system_dir: &str) -> ApiSetMap {
    let Some(data) = read_section(Path::new(system_dir).join("apisetschema.dll")) else {
        return ApiSetMap::default();
    };
    let mut map = parse(&data);
    if map.is_empty() {
        return map;
    }
    for subkey in super::registry::subkeys(EXTENSIONS_KEY) {
        let key = format!(r"{EXTENSIONS_KEY}\{subkey}");
        let Some(file) = super::registry::string(&key, "FileName") else {
            continue;
        };
        if let Some(data) = read_section(Path::new(system_dir).join(file)) {
            map.merge(parse_extension(&data));
        }
    }
    map
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

    fn value(host: &str) -> ApiSetValue {
        ApiSetValue {
            alias: String::new(),
            host: host.to_string(),
        }
    }

    // An extension in the layout of the Windows 11 24H2 ones, with a set of
    // a single host for each of the SETS.
    fn extension(sets: &[(&str, &str)]) -> Vec<u8> {
        let entries = EXTENSION_HEADER_SIZE;
        let values = entries + sets.len() * EXTENSION_ENTRY_SIZE;
        let mut data = vec![0u8; values + sets.len() * EXTENSION_VALUE_SIZE];
        data[0..2].copy_from_slice(&EXTENSION_VERSION.to_le_bytes());
        data[2..4].copy_from_slice(&2u16.to_le_bytes());
        put_u32(&mut data, 12, entries as u32);
        data[18..20].copy_from_slice(&(sets.len() as u16).to_le_bytes());
        for (i, (name, host)) in sets.iter().enumerate() {
            let entry = entries + i * EXTENSION_ENTRY_SIZE;
            let value = values + i * EXTENSION_VALUE_SIZE;
            let (host_o, host_l) = put_str(&mut data, host);
            let name_o = data.len() as u32;
            data.extend_from_slice(name.as_bytes());
            data.push(0);
            put_u32(&mut data, entry, name_o);
            put_u32(&mut data, entry + 4, value as u32);
            data[entry + 8..entry + 10].copy_from_slice(&(name.len() as u16).to_le_bytes());
            data[entry + 10..entry + 12].copy_from_slice(&1u16.to_le_bytes());
            put_u32(&mut data, value, host_o);
            put_u32(&mut data, value + 8, host_l / 2);
        }
        data
    }

    #[test]
    fn parse_extension_sets() {
        let data = extension(&[
            ("ext-ms-win-a-l1-1-1", "a.dll"),
            ("ext-ms-win-b-l1-2-0", "b.sys"),
        ]);
        assert_eq!(
            parse_extension(&data),
            [
                ("ext-ms-win-a-l1-1-1".to_string(), vec![value("a.dll")]),
                ("ext-ms-win-b-l1-2-0".to_string(), vec![value("b.sys")]),
            ]
        );
        // Another layout, and a truncated one, give nothing.
        let mut other = data.clone();
        other[0] = 6;
        assert!(parse_extension(&other).is_empty());
        assert!(parse_extension(&data[..10]).is_empty());
    }

    // An extension provides the hosts of the unsealed sets only, and adds no
    // set.
    #[test]
    fn merge_extensions() {
        let entry = |sealed, host: &str| ApiSetEntry {
            sealed,
            values: vec![value(host)],
        };
        let mut map = ApiSetMap {
            entries: HashMap::from([
                (key("ext-ms-win-open-l1-1-1"), entry(false, "")),
                (key("ext-ms-win-sealed-l1-1-0"), entry(true, "base.dll")),
            ]),
            version: NAMESPACE_V6,
            extensions: 0,
        };
        let data = extension(&[
            ("ext-ms-win-open-l1-1-1", "open.dll"),
            ("ext-ms-win-sealed-l1-1-0", "other.dll"),
            ("ext-ms-win-new-l1-1-0", "new.dll"),
        ]);
        map.merge(parse_extension(&data));
        assert_eq!(map.extensions(), 1);
        // A set is looked up by any revision.
        assert_eq!(
            map.resolve("ext-ms-win-open-l1-1-0.dll", "x.dll"),
            Some("open.dll")
        );
        assert_eq!(
            map.resolve("ext-ms-win-sealed-l1-1-0.dll", "x.dll"),
            Some("base.dll")
        );
        assert_eq!(map.resolve("ext-ms-win-new-l1-1-0.dll", "x.dll"), None);
        assert_eq!(map.len(), 2);
    }

    // The namespace the kernel maps in the process, which the PEB points at.
    #[cfg(target_arch = "x86_64")]
    fn process_namespace() -> &'static [u8] {
        let peb: *const u8;
        // SAFETY: GS points at the TEB of the thread on x86_64 Windows, which
        // holds the PEB address at 0x60.
        unsafe { std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb) };
        // SAFETY: the PEB holds the ApiSetMap pointer at 0x68, which points
        // at a namespace mapped read only for the process lifetime, whose
        // size is its second field.
        unsafe {
            let namespace = *(peb.add(0x68) as *const *const u8);
            let size = *(namespace.add(4) as *const u32);
            std::slice::from_raw_parts(namespace, size as usize)
        }
    }

    // The base schema merged with the extensions is the namespace the kernel
    // hands the processes.
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn merged_schema_is_the_process_one() {
        let system = crate::pe::search_dirs::system_dir(
            &crate::pe::search_dirs::windows_dir(),
            crate::pe::machine::Wow64::Native,
        );
        let merged = load(&system);
        let process = parse(process_namespace());
        assert_eq!(merged.len(), process.len());
        for (name, entry) in &process.entries {
            let values = merged.entries.get(name).map(|entry| &entry.values);
            assert_eq!(values, Some(&entry.values), "{name}");
        }
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
        // A multi-byte character over the prefix boundary.
        assert!(!is_apiset("ñoñTIME140.dll"));
        assert!(!is_apiset("apiñ-x.dll"));
    }

    #[test]
    fn namespace_key() {
        assert_eq!(key("API-MS-Win-Test-L1-1-0.dll"), "api-ms-win-test-l1-1");
        assert_eq!(key("noversion"), "noversion");
    }
}
