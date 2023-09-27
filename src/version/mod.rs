use common::*;
use std::ffi::c_void;
use windows::{core::*, Win32::Foundation::*, Win32::Storage::FileSystem::*};

pub fn get_file_version_info(
    value_name: PCWSTR,
    module_name: PCWSTR,
) -> StdResult<String, Box<dyn StdError>> {
    if value_name.is_null() || module_name.is_null() {
        return Err(WRUE::new(
            1,
            "Version".into(),
            "value_name or module_name is invalid".into(),
        )
        .into());
    }
    unsafe {
        dbg!(
            value_name.to_string().unwrap(),
            module_name.to_string().unwrap()
        );
    }
    let mut handle = 0_u32;
    unsafe {
        let data_size = GetFileVersionInfoSizeW(module_name, Some(&mut handle));
        if data_size == 0 {
            return Err(WRUE::new(2, "Version".into(), "data size is zero".into()).into());
        }
        let mut buff = vec![0_u8; data_size as usize];
        GetFileVersionInfoW(
            module_name,
            handle,
            data_size,
            buff.as_mut_ptr() as *mut c_void,
        )?;
        let mut data_size = 0_u32;
        let mut data_table: *mut u32 = std::ptr::null_mut();
        let ret = VerQueryValueW(
            buff.as_mut_ptr() as *mut c_void,
            w!("\\VarFileInfo\\Translation"),
            &mut data_table as *mut *mut u32 as *mut *mut c_void,
            &mut data_size as *mut u32,
        );
        if ret == BOOL::default() {
            return Err(WRUE::new(3, "Version".into(), "query value size failed".into()).into());
        }
        let lang_char_set = (*data_table >> 16) | (*data_table << 16);
        let str = format!(
            "\\StringFileInfo\\{:08x}\\{}",
            lang_char_set,
            value_name.to_string().unwrap()
        );
        let mut str: Vec<u16> = str.encode_utf16().collect();
        str.push(0_u16);
        let utf16_str = PCWSTR::from_raw(str.as_ptr());
        let mut pdata: *mut u8 = std::ptr::null_mut();
        let ret = VerQueryValueW(
            buff.as_mut_ptr() as *mut c_void,
            utf16_str,
            &mut pdata as *mut *mut u8 as *mut *mut c_void,
            &mut data_size as *mut u32,
        );
        if ret == BOOL::default() {
            return Err(WRUE::new(4, "Version".into(), "query value data failed".into()).into());
        }
        Ok(PCWSTR::from_raw(pdata as *const u16)
            .to_string()
            .unwrap_or_else(|_| String::from("")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time};

    #[test]
    fn test_version() {
        loop {
            let ret =
                get_file_version_info(w!("FileDescription"), w!("C:\\Windows\\System32\\cmd.exe"));
            dbg!(&ret);
            assert_ne!(ret.unwrap_or(String::from("")), String::from(""));
            let ret =
                get_file_version_info(w!("CompanyName"), w!("C:\\Windows\\System32\\cmd.exe"));
            dbg!(&ret);
            assert_ne!(ret.unwrap_or(String::from("")), String::from(""));
            let ret =
                get_file_version_info(w!("LegalCopyright"), w!("C:\\Windows\\System32\\cmd.exe"));
            dbg!(&ret);
            assert_ne!(ret.unwrap_or(String::from("")), String::from(""));
            thread::sleep(time::Duration::from_secs(1));
            break;
        }
    }
}
