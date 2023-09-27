use common::*;
use std::mem::size_of;
use windows::{core::*, Win32::System::Registry::*};

pub fn set_registry_value(
    key: HKEY,
    sub_key: PCWSTR,
    value_name: PCWSTR,
    value_type: REG_VALUE_TYPE,
    data: Option<&[u8]>,
) -> StdResult<(), Box<dyn StdError>> {
    if key.is_invalid() {
        return Err(WRUE::new(1, "Registry".into(), "key is invalid".into()).into());
    }
    if sub_key.is_null() {
        return Err(WRUE::new(2, "Registry".into(), "sub_key is null".into()).into());
    }
    if value_name.is_null() {
        return Err(WRUE::new(3, "Registry".into(), "value_name is null".into()).into());
    }
    if value_type == REG_NONE {
        return Err(WRUE::new(4, "Registry".into(), "value_type is REG_NONE".into()).into());
    }
    if data == None {
        return Err(WRUE::new(5, "Registry".into(), "data is None".into()).into());
    }
    unsafe {
        let mut hkey_result: HKEY = HKEY::default();
        let ret = RegOpenKeyExW(
            key,
            sub_key,
            0_u32,
            KEY_WRITE,
            &mut hkey_result as *mut HKEY,
        );
        if let Err(e) = ret {
            dbg!(e);
            RegCreateKeyW(key, sub_key, &mut hkey_result as *mut HKEY)?;
        }
        let ret = RegSetValueExW(hkey_result, value_name, 0_u32, value_type, data);
        let ret_close = RegCloseKey(hkey_result);
        dbg!(&ret_close);
        match ret {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

pub fn query_registry_value(
    key: HKEY,
    sub_key: PCWSTR,
    value_name: PCWSTR,
) -> StdResult<(REG_VALUE_TYPE, Vec<u8>), Box<dyn StdError>> {
    if key.is_invalid() {
        return Err(WRUE::new(6, "Registry".into(), "key is invalid".into()).into());
    }
    if sub_key.is_null() {
        return Err(WRUE::new(7, "Registry".into(), "sub_key is null".into()).into());
    }
    if value_name.is_null() {
        return Err(WRUE::new(8, "Registry".into(), "value_name is null".into()).into());
    }
    unsafe {
        let mut hkey_result: HKEY = HKEY::default();
        RegOpenKeyExW(key, sub_key, 0_u32, KEY_READ, &mut hkey_result as *mut HKEY)?;
        let mut len = 0_u32;
        let lpcbdata: Option<*mut u32> = Some(&mut len);
        let ret = RegQueryValueExW(hkey_result, value_name, None, None, None, lpcbdata);
        if let Err(e) = ret {
            let ret_close = RegCloseKey(hkey_result);
            dbg!(&ret_close);
            dbg!(&e);
            return Err(e.into());
        }
        let mut reg_type = REG_NONE;
        let mut data = vec![0_u8; (len as usize + 1) * size_of::<u16>()];
        let lptype: Option<*mut REG_VALUE_TYPE> = Some(&mut reg_type);
        let lpdata: Option<*mut u8> = Some(data.as_mut_ptr());
        let ret = RegQueryValueExW(hkey_result, value_name, None, lptype, lpdata, lpcbdata);
        let ret_close = RegCloseKey(hkey_result);
        dbg!(&ret_close);
        if let Err(e) = ret {
            return Err(e.into());
        }
        Ok((reg_type, data))
    }
}

pub fn delete_registry_value(
    key: HKEY,
    sub_key: PCWSTR,
    value_name: PCWSTR,
) -> StdResult<(), Box<dyn StdError>> {
    if key.is_invalid() {
        return Err(WRUE::new(9, "Registry".into(), "key is invalid".into()).into());
    }
    if sub_key.is_null() {
        return Err(WRUE::new(10, "Registry".into(), "sub_key is null".into()).into());
    }
    unsafe {
        if value_name.is_null() {
            return match RegDeleteKeyW(key, sub_key) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.into()),
            };
        }
        let mut hkey_result: HKEY = HKEY::default();
        RegOpenKeyExW(
            key,
            sub_key,
            0_u32,
            KEY_WRITE,
            &mut hkey_result as *mut HKEY,
        )?;
        let ret = RegDeleteValueW(hkey_result, value_name);
        let ret_close = RegCloseKey(hkey_result);
        dbg!(&ret_close);
        match ret {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry() {
        let utf16_str = w!("收到房间号sf123南方的鈤yu😂1");
        let slice_utf16 = unsafe {
            std::slice::from_raw_parts(
                utf16_str.as_ptr() as *const u8,
                wcslen(utf16_str) * size_of::<u16>(),
            )
        };
        let ret = set_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            w!("test_sz_value"),
            REG_SZ,
            Some(slice_utf16),
        );
        assert_eq!(ret.is_ok(), true);
        // let u8_vec: Vec<u8> = 12429_u32.iter().flat_map(|&x| x.to_le_bytes().to_vec()).collect();
        let ret = set_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            w!("test_dword_value"),
            REG_DWORD,
            Some(&(722536_u32.to_le_bytes()[..])),
        );
        assert_eq!(ret.is_ok(), true);
        let ret = query_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            w!("test_dword_value"),
        );
        assert_eq!(ret.is_ok(), true);
        match ret {
            Ok((reg_type, reg_data)) => {
                dbg!(reg_type);
                if reg_type == REG_DWORD {
                    unsafe {
                        assert_eq!(*(reg_data.as_ptr() as *const u32), 722536_u32);
                    }
                }
            }
            Err(e) => {
                assert_ne!(e.to_string(), "");
            }
        }

        let ret = query_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            w!("test_sz_value"),
        );
        assert_eq!(ret.is_ok(), true);
        match ret {
            Ok((reg_type, reg_data)) => {
                dbg!(reg_type);
                if reg_type == REG_SZ {
                    unsafe {
                        dbg!(PCWSTR::from_raw(reg_data.as_ptr() as *const u16)
                            .to_string()
                            .unwrap());
                        assert_eq!(
                            PCWSTR::from_raw(reg_data.as_ptr() as *const u16)
                                .to_string()
                                .unwrap(),
                            utf16_str.to_string().unwrap()
                        );
                    }
                }
            }
            Err(e) => {
                assert_ne!(e.to_string(), "");
            }
        }
        let ret = delete_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            w!("test_sz_value"),
        );
        assert_eq!(ret.is_ok(), true);
        let ret = delete_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            w!("test_dword_value"),
        );
        assert_eq!(ret.is_ok(), true);
        let ret = delete_registry_value(
            HKEY_CURRENT_USER,
            w!("SOFTWARE\\test_rust0916"),
            PCWSTR::null(),
        );
        assert_eq!(ret.is_ok(), true);
    }
}
