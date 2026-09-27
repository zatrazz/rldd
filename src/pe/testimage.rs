// Minimal PE images for the tests, built by hand: the headers and a single
// section holding the data the test lays out, with the data directories
// pointing inside it.

use object::pe;

// Where the section is mapped and where it starts in the file.
pub const SECTION_RVA: u32 = 0x1000;
const HEADERS: usize = 0x200;

pub struct Image {
    pub machine: pe::Machine,
    pub pe64: bool,
    pub characteristics: u16,
    pub image_base: u64,
    // The data directories, as the index, the offset in the section, and the
    // size.
    pub dirs: Vec<(usize, u32, u32)>,
    pub section: Vec<u8>,
}

impl Image {
    pub fn new(machine: pe::Machine, pe64: bool, characteristics: u16) -> Self {
        Image {
            machine,
            pe64,
            characteristics: characteristics | pe::IMAGE_FILE_EXECUTABLE_IMAGE.0,
            image_base: 0x1_4000_0000,
            dirs: Vec::new(),
            section: Vec::new(),
        }
    }

    pub fn dll(machine: pe::Machine, pe64: bool) -> Self {
        Self::new(machine, pe64, pe::IMAGE_FILE_DLL.0)
    }

    pub fn exe(machine: pe::Machine, pe64: bool) -> Self {
        Self::new(machine, pe64, 0)
    }

    // Append DATA to the section, aligned to 8 bytes, returning its offset.
    pub fn add(&mut self, data: &[u8]) -> u32 {
        while !self.section.len().is_multiple_of(8) {
            self.section.push(0);
        }
        let offset = self.section.len() as u32;
        self.section.extend_from_slice(data);
        offset
    }

    // Append DATA and point the INDEX data directory at it.
    pub fn directory(&mut self, index: usize, data: &[u8]) -> u32 {
        let offset = self.add(data);
        self.dirs.push((index, offset, data.len() as u32));
        offset
    }

    // The RVA of OFFSET in the section.
    pub fn rva(offset: u32) -> u32 {
        SECTION_RVA + offset
    }

    // The RVA the next data added lands at.
    pub fn next_rva(&self) -> u32 {
        Self::rva(self.section.len().next_multiple_of(8) as u32)
    }

    // Append a NUL terminated string, returning its RVA.
    pub fn string(&mut self, string: &[u8]) -> u32 {
        let mut data = string.to_vec();
        data.push(0);
        Self::rva(self.add(&data))
    }

    // Append a hint/name entry, returning its RVA.
    pub fn hint_name(&mut self, name: &[u8]) -> u32 {
        let mut data = vec![0, 0];
        data.extend_from_slice(name);
        data.push(0);
        Self::rva(self.add(&data))
    }

    // Append a NUL terminated thunk array, returning its RVA.
    pub fn thunks(&mut self, thunks: &[u64]) -> u32 {
        let mut data = Vec::new();
        for thunk in thunks.iter().chain(&[0]) {
            match self.pe64 {
                true => data.extend_from_slice(&thunk.to_le_bytes()),
                false => data.extend_from_slice(&(*thunk as u32).to_le_bytes()),
            }
        }
        Self::rva(self.add(&data))
    }

    // The import directory, with a descriptor of the original first thunk,
    // the timestamp, the name and the first thunk for each entry.
    pub fn imports(&mut self, descriptors: &[[u32; 4]]) {
        let mut data = Vec::new();
        for [original, timestamp, name, first] in descriptors.iter().chain(&[[0; 4]]) {
            for field in [*original, *timestamp, 0, *name, *first] {
                data.extend_from_slice(&field.to_le_bytes());
            }
        }
        self.directory(pe::IMAGE_DIRECTORY_ENTRY_IMPORT, &data);
    }

    // The delay load import directory, with the attributes, the name, the
    // module handle, the address table and the name table of each entry.
    pub fn delay_imports(&mut self, descriptors: &[[u32; 5]]) {
        let mut data = Vec::new();
        for descriptor in descriptors.iter().chain(&[[0; 5]]) {
            for field in descriptor.iter().chain(&[0, 0, 0]) {
                data.extend_from_slice(&field.to_le_bytes());
            }
        }
        self.directory(pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, &data);
    }

    pub fn build(&self) -> Vec<u8> {
        let (optional, dirs_at, image_base_at) = match self.pe64 {
            true => (240usize, 112usize, 24usize),
            false => (224, 96, 28),
        };
        let size = HEADERS + self.section.len().max(1);
        let mut data = vec![0u8; size];
        let mut put = |offset: usize, bytes: &[u8]| {
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
        };

        put(0, b"MZ");
        put(0x3c, &0x40u32.to_le_bytes());
        put(0x40, b"PE\0\0");
        let file = 0x44;
        put(file, &self.machine.0.to_le_bytes());
        put(file + 2, &1u16.to_le_bytes());
        put(file + 16, &(optional as u16).to_le_bytes());
        put(file + 18, &self.characteristics.to_le_bytes());

        let opt = file + 20;
        let magic = match self.pe64 {
            true => pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            false => pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        };
        put(opt, &magic.to_le_bytes());
        match self.pe64 {
            true => put(opt + image_base_at, &self.image_base.to_le_bytes()),
            false => put(opt + image_base_at, &(self.image_base as u32).to_le_bytes()),
        }
        put(opt + 32, &0x1000u32.to_le_bytes());
        put(opt + 36, &(HEADERS as u32).to_le_bytes());
        put(opt + 48, &6u16.to_le_bytes());
        let image_size = SECTION_RVA + (self.section.len() as u32).next_multiple_of(0x1000);
        put(opt + 56, &image_size.to_le_bytes());
        put(opt + 60, &(HEADERS as u32).to_le_bytes());
        put(opt + 68, &pe::IMAGE_SUBSYSTEM_WINDOWS_CUI.0.to_le_bytes());
        put(opt + dirs_at - 4, &16u32.to_le_bytes());
        for (index, offset, len) in &self.dirs {
            let at = opt + dirs_at + index * 8;
            put(at, &(SECTION_RVA + offset).to_le_bytes());
            put(at + 4, &len.to_le_bytes());
        }

        let section = opt + optional;
        put(section, b".data\0\0\0");
        put(section + 8, &(self.section.len() as u32).to_le_bytes());
        put(section + 12, &SECTION_RVA.to_le_bytes());
        put(section + 16, &(self.section.len() as u32).to_le_bytes());
        put(section + 20, &(HEADERS as u32).to_le_bytes());
        put(
            section + 36,
            &(pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0 | pe::IMAGE_SCN_MEM_READ.0).to_le_bytes(),
        );

        put(HEADERS, &self.section);
        data
    }

    // Add a resource directory holding the RT_MANIFEST resources, one per ID.
    pub fn manifests(&mut self, manifests: &[(u16, &[u8])]) {
        // The directory tables and their entries come first, then the data
        // entries, then the data, so the offsets are known up front.
        let table = |entries: usize| 16 + entries * 8;
        let root = 0;
        let types = root + table(1);
        let languages = types + table(manifests.len());
        let entries = languages + manifests.len() * table(1);
        let contents = entries + manifests.len() * 16;

        let mut rsrc = vec![0u8; contents];
        let mut put = |offset: usize, value: u32| {
            rsrc[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        // The number of ID entries is the high half of the second word.
        put(root + 12, 1 << 16);
        put(root + 16, u32::from(pe::RT_MANIFEST));
        put(
            root + 20,
            types as u32 | pe::IMAGE_RESOURCE_DATA_IS_DIRECTORY,
        );
        put(types + 12, (manifests.len() as u32) << 16);

        let base = self.section.len().next_multiple_of(8);
        let mut data = Vec::new();
        for (i, (id, manifest)) in manifests.iter().enumerate() {
            let language = languages + i * table(1);
            let entry = entries + i * 16;
            put(types + 16 + i * 8, u32::from(*id));
            put(
                types + 20 + i * 8,
                language as u32 | pe::IMAGE_RESOURCE_DATA_IS_DIRECTORY,
            );
            put(language + 12, 1 << 16);
            put(language + 16, 0x409);
            put(language + 20, entry as u32);
            let offset = (base + contents + data.len()) as u32;
            put(entry, Self::rva(offset));
            put(entry + 4, manifest.len() as u32);
            data.extend_from_slice(manifest);
        }
        rsrc.extend_from_slice(&data);
        self.directory(pe::IMAGE_DIRECTORY_ENTRY_RESOURCE, &rsrc);
    }
}
