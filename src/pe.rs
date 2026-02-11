use std::mem;

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(C)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

#[repr(C)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: [u8; 1],
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x4550;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

pub const IMAGE_ORDINAL_FLAG: u64 = 0x8000000000000000;
pub const IMAGE_REL_BASED_DIR64: u8 = 10;
pub const IMAGE_REL_BASED_HIGHLOW: u8 = 3;

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;

pub struct PeParser {
    pub data: Vec<u8>,
}

impl PeParser {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn validate(&self) -> Result<&ImageNtHeaders64, String> {
        // Check minimum size
        if self.data.len() < mem::size_of::<ImageDosHeader>() {
            return Err(format!(
                "Error: File too small to be a valid DLL (size: {})",
                self.data.len()
            ));
        }

        // Parse DOS header
        let dos_header = self.get_dos_header()?;

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(format!(
                "Error: Invalid DOS signature. Expected: 0x{:X}, Got: 0x{:X}",
                IMAGE_DOS_SIGNATURE, dos_header.e_magic
            ));
        }

        println!("[+] DOS header valid");

        // Check e_lfanew bounds
        if (dos_header.e_lfanew as usize) >= self.data.len() {
            return Err("Error: PE header offset out of bounds".to_string());
        }

        // Parse NT headers
        let nt_headers = self.get_nt_headers()?;

        if nt_headers.signature != IMAGE_NT_SIGNATURE {
            return Err(format!(
                "Error: Invalid NT signature. Expected: 0x{:X}, Got: 0x{:X}",
                IMAGE_NT_SIGNATURE, nt_headers.signature
            ));
        }

        println!("[+] NT header valid");

        // Check architecture
        #[cfg(target_arch = "x86_64")]
        let expected_machine = IMAGE_FILE_MACHINE_AMD64;
        #[cfg(target_arch = "x86")]
        let expected_machine = IMAGE_FILE_MACHINE_I386;

        println!(
            "[*] DLL Machine type: 0x{:X}",
            nt_headers.file_header.machine
        );

        if nt_headers.file_header.machine != expected_machine {
            return Err(format!(
                "Error: Architecture mismatch. Expected: 0x{:X}, Got: 0x{:X}",
                expected_machine, nt_headers.file_header.machine
            ));
        }

        println!("[+] Architecture matches");
        println!(
            "[*] Image Base: 0x{:X}",
            nt_headers.optional_header.image_base
        );

        Ok(nt_headers)
    }

    pub fn get_dos_header(&self) -> Result<&ImageDosHeader, String> {
        unsafe {
            let ptr = self.data.as_ptr() as *const ImageDosHeader;
            Ok(&*ptr)
        }
    }

    pub fn get_nt_headers(&self) -> Result<&ImageNtHeaders64, String> {
        let dos_header = self.get_dos_header()?;
        unsafe {
            let offset = dos_header.e_lfanew as usize;
            let ptr = self.data.as_ptr().add(offset) as *const ImageNtHeaders64;
            Ok(&*ptr)
        }
    }

    pub fn get_section_headers(&self) -> Result<Vec<ImageSectionHeader>, String> {
        let nt_headers = self.get_nt_headers()?;
        let num_sections = nt_headers.file_header.number_of_sections as usize;

        unsafe {
            let sections_offset = self.data.as_ptr() as usize
                + (dos_header_e_lfanew(&self.data) as usize)
                + mem::size_of::<u32>()
                + mem::size_of::<ImageFileHeader>()
                + nt_headers.file_header.size_of_optional_header as usize;

            let mut sections = Vec::with_capacity(num_sections);
            for i in 0..num_sections {
                let ptr = self.data.as_ptr().add(sections_offset + i * mem::size_of::<ImageSectionHeader>())
                    as *const ImageSectionHeader;
                sections.push(ptr.read());
            }
            Ok(sections)
        }
    }
}

fn dos_header_e_lfanew(data: &[u8]) -> i32 {
    unsafe {
        let dos_header = data.as_ptr() as *const ImageDosHeader;
        (*dos_header).e_lfanew
    }
}
