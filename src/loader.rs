use crate::pe::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::LibraryLoader::*;
use windows::core::PCSTR;
use std::ptr;
use std::mem;

pub struct Loader {
    pub base: *mut u8,
    pub nt_headers: *const ImageNtHeaders64,
    pub image_size: usize,
}

impl Loader {
    pub unsafe fn load(data: &[u8]) -> Result<Self, String> {
        let dos_header = data.as_ptr() as *const ImageDosHeader;
        let nt_headers_offset = (*dos_header).e_lfanew as usize;
        let nt_headers = data.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders64;

        let image_size = (*nt_headers).optional_header.size_of_image as usize;

        if image_size == 0 {
            return Err("Error: Invalid image size (0 bytes)".to_string());
        }

        if image_size > 500 * 1024 * 1024 {
            return Err(format!(
                "Error: DLL too large ({} MB)",
                image_size / 1024 / 1024
            ));
        }

        println!("[*] Image Size: {} bytes", image_size);

        // Allocate memory
        let base = VirtualAlloc(
            None,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) as *mut u8;

        if base.is_null() {
            return Err("Error: Failed to allocate memory".to_string());
        }

        println!("[+] Allocated {} bytes at 0x{:X}", image_size, base as usize);

        // Copy headers
        let headers_size = (*nt_headers).optional_header.size_of_headers as usize;
        if headers_size > image_size {
            VirtualFree(base as _, 0, MEM_RELEASE);
            return Err("Error: Header size exceeds image size".to_string());
        }

        ptr::copy_nonoverlapping(data.as_ptr(), base, headers_size);
        println!("[+] Headers copied");

        // Load sections
        println!("\n[*] Loading sections...");

        let section_header = (data.as_ptr() as usize
            + nt_headers_offset
            + mem::size_of::<u32>()
            + mem::size_of::<ImageFileHeader>()
            + (*nt_headers).file_header.size_of_optional_header as usize)
            as *const ImageSectionHeader;

        for i in 0..(*nt_headers).file_header.number_of_sections {
            let section = &*section_header.add(i as usize);

            let section_name = String::from_utf8_lossy(
                &section.name[..section.name.iter().position(|&x| x == 0).unwrap_or(8)],
            );

            let dest = base.add(section.virtual_address as usize);
            let src = data.as_ptr().add(section.pointer_to_raw_data as usize);
            let size = section.size_of_raw_data as usize;

            // Bounds checking
            if section.pointer_to_raw_data as usize + size > data.len() {
                VirtualFree(base as _, 0, MEM_RELEASE);
                return Err(format!(
                    "Error: Section {} extends beyond file boundary",
                    section_name
                ));
            }

            if dest.add(size) as usize > base.add(image_size) as usize {
                VirtualFree(base as _, 0, MEM_RELEASE);
                return Err(format!(
                    "Error: Section {} extends beyond allocated memory",
                    section_name
                ));
            }

            ptr::copy_nonoverlapping(src, dest, size);
            println!("[+] Loaded section: {}", section_name);
        }

        Ok(Self {
            base,
            nt_headers,
            image_size,
        })
    }

    pub unsafe fn resolve_imports(&mut self) -> Result<(), String> {
        println!("\n[*] Processing import table...");

        let import_dir = &(*self.nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if import_dir.virtual_address == 0 {
            println!("[!] No import table found");
            return Ok(());
        }

        let import_desc = self.base.add(import_dir.virtual_address as usize)
            as *const ImageImportDescriptor;

        let mut lib_count = 0;
        let mut func_count = 0;

        let mut current_desc = import_desc;
        while (*current_desc).name != 0 {
            let lib_name_ptr = self.base.add((*current_desc).name as usize);
            let lib_name = std::ffi::CStr::from_ptr(lib_name_ptr as *const i8);
            let lib_name_str = lib_name.to_string_lossy();

            println!("[*] Loading library: {}", lib_name_str);

            // Load library
            let lib_handle = LoadLibraryA(PCSTR(lib_name.as_ptr() as *const u8))
                .map_err(|e| format!("Error: Failed to load library: {} - {:?}", lib_name_str, e))?;

            lib_count += 1;

            // Resolve imports
            let mut orig_thunk = self.base.add((*current_desc).original_first_thunk as usize)
                as *const u64;
            let mut thunk = self.base.add((*current_desc).first_thunk as usize)
                as *mut u64;

            while *thunk != 0 {
                let mut func_name: Option<&str> = None;

                if *orig_thunk & IMAGE_ORDINAL_FLAG != 0 {
                    // Import by ordinal
                    let ordinal = (*orig_thunk & 0xFFFF) as u16;
                    let ordinal_ptr = ordinal as *const u8;
                    let addr = GetProcAddress(lib_handle, PCSTR(ordinal_ptr));
                    *thunk = addr.map_or(0, |a| a as usize as u64);
                    func_name = Some("(by ordinal)");
                } else {
                    // Import by name
                    let import_by_name = self.base.add(*orig_thunk as usize & 0xFFFFFFFF)
                        as *const ImageImportByName;
                    let name_ptr = &(*import_by_name).name as *const u8;
                    func_name = Some(std::ffi::CStr::from_ptr(name_ptr as *const i8).to_str().unwrap_or("?"));

                    let addr = GetProcAddress(lib_handle, PCSTR(name_ptr));
                    if addr.is_none() {
                        return Err(format!(
                            "Error: Failed to resolve function: {}!{}",
                            lib_name_str,
                            func_name.unwrap_or("?")
                        ));
                    }
                    *thunk = addr.unwrap() as usize as u64;
                }

                func_count += 1;
                orig_thunk = orig_thunk.add(1);
                thunk = thunk.add(1);
            }

            current_desc = current_desc.add(1);
        }

        println!(
            "[+] Resolved {} functions from {} libraries",
            func_count, lib_count
        );

        Ok(())
    }

    pub unsafe fn apply_relocations(&mut self) -> Result<(), String> {
        let delta = self.base as u64 - (*self.nt_headers).optional_header.image_base;

        if delta == 0 {
            return Ok(());
        }

        println!("[*] Applying relocations (delta: 0x{:X})...", delta);

        let reloc_dir = &(*self.nt_headers).optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if reloc_dir.size == 0 {
            println!("[!] No relocations found");
            return Ok(());
        }

        let mut reloc_block = self.base.add(reloc_dir.virtual_address as usize)
            as *const ImageBaseRelocation;

        while (*reloc_block).virtual_address != 0 {
            let entries_count = ((*reloc_block).size_of_block as usize
                - mem::size_of::<ImageBaseRelocation>())
                / mem::size_of::<u16>();

            let entries = self.base.add(
                (reloc_block as usize - self.base as usize) + mem::size_of::<ImageBaseRelocation>()
            ) as *const u16;

            for i in 0..entries_count {
                let entry = *entries.add(i);
                let reloc_type = (entry >> 12) as u8;
                let offset = (entry & 0xFFF) as usize;

                if reloc_type == IMAGE_REL_BASED_DIR64 {
                    let patch_addr = self.base.add(
                        (*reloc_block).virtual_address as usize + offset
                    ) as *mut u64;
                    *patch_addr += delta;
                } else if reloc_type == IMAGE_REL_BASED_HIGHLOW {
                    let patch_addr = self.base.add(
                        (*reloc_block).virtual_address as usize + offset
                    ) as *mut u32;
                    *patch_addr += delta as u32;
                }
            }

            reloc_block = self.base.add(
                reloc_block as usize - self.base as usize + (*reloc_block).size_of_block as usize
            ) as *const ImageBaseRelocation;
        }

        println!("[+] Relocations applied");
        Ok(())
    }

    pub unsafe fn fix_memory_protections(&mut self) -> Result<(), String> {
        let section_header = (self.base as usize
            + ((*self.nt_headers).signature as usize)
            + mem::size_of::<ImageFileHeader>()
            + (*self.nt_headers).file_header.size_of_optional_header as usize)
            as *const ImageSectionHeader;

        for i in 0..(*self.nt_headers).file_header.number_of_sections {
            let section = &*section_header.add(i as usize);

            let protection = if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                PAGE_EXECUTE_READ
            } else if section.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                PAGE_READWRITE
            } else if section.characteristics & IMAGE_SCN_MEM_READ != 0 {
                PAGE_READONLY
            } else {
                PAGE_READWRITE
            };

            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(
                self.base.add(section.virtual_address as usize) as _,
                section.virtual_size as usize,
                protection,
                &mut old_protect,
            );
        }

        Ok(())
    }

    pub fn get_entry_point(&self) -> *const u8 {
        unsafe {
            self.base.add((*self.nt_headers).optional_header.address_of_entry_point as usize)
        }
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        // Note: We don't free the memory here as the DLL may still be running
        // The caller is responsible for cleanup when appropriate
    }
}
