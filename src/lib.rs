mod icon;
mod registry;
mod sign;
mod version;
mod wmi;

use icon::*;
use registry::*;
use sign::*;
use std::ffi::CStr;
use std::os::raw::c_char;
use version::*;
use windows::{
    core::*, Win32::Foundation::*, Win32::System::LibraryLoader::*, Win32::System::Registry::*,
};
use wmi::*;

#[no_mangle]
pub extern "C" fn SaveExeIcon(file_name: *const c_char, icon_path: *const c_char) -> u32 {
    if file_name.is_null() || icon_path.is_null() {
        return 1;
    }
    let file_name_vec16 = cstr_to_vec16(file_name);
    let file_name_pcwstr = PCWSTR::from_raw(file_name_vec16.as_ptr());
    let icon_vec16 = cstr_to_vec16(icon_path);
    let icon_path_pcwstr = PCWSTR::from_raw(icon_vec16.as_ptr());
    if file_name_pcwstr.is_null() || icon_path_pcwstr.is_null() {
        return 2;
    }
    let ret = save_exe_icon(file_name_pcwstr, icon_path_pcwstr);
    dbg!(&ret);
    match ret {
        Ok(_) => {
            return 0;
        }
        Err(_) => {
            return 3;
        }
    }
}

#[no_mangle]
pub extern "C" fn SetRegistryValue(
    key: HKEY,
    sub_key: *const c_char,
    value_name: *const c_char,
    value_type: u32,
    data: *const u8,
    len: usize,
) -> u32 {
    if key == HKEY::default()
        || sub_key.is_null()
        || value_name.is_null()
        || value_type == 0
        || data.is_null()
        || len == 0
    {
        return 1;
    }
    let sub_key_vec16 = cstr_to_vec16(sub_key);
    let sub_key_pcwstr = PCWSTR::from_raw(sub_key_vec16.as_ptr());
    let value_name_vec16 = cstr_to_vec16(value_name);
    let value_name_pcwstr = PCWSTR::from_raw(value_name_vec16.as_ptr());
    let slice_data = unsafe { std::slice::from_raw_parts(data, len) };
    let ret = set_registry_value(
        key,
        sub_key_pcwstr,
        value_name_pcwstr,
        REG_VALUE_TYPE(value_type),
        Some(slice_data),
    );
    match ret {
        Ok(_) => {
            return 0;
        }
        Err(_) => {
            return 2;
        }
    }
}

#[no_mangle]
pub extern "C" fn QueryRegistryValue(
    key: HKEY,
    sub_key: *const c_char,
    value_name: *const c_char,
    value_type: *mut u32,
    data: *mut u8,
    len: *mut u32,
) -> u32 {
    if key == HKEY::default()
        || sub_key.is_null()
        || value_name.is_null()
        || value_type.is_null()
        || len.is_null()
    {
        return 1;
    }
    let sub_key_vec16 = cstr_to_vec16(sub_key);
    let sub_key_pcwstr = PCWSTR::from_raw(sub_key_vec16.as_ptr());
    let value_name_vec16 = cstr_to_vec16(value_name);
    let value_name_pcwstr = PCWSTR::from_raw(value_name_vec16.as_ptr());
    let ret = query_registry_value(key, sub_key_pcwstr, value_name_pcwstr);
    match ret {
        Ok((reg_type, mut reg_data)) => {
            unsafe {
                *value_type = reg_type.0;
                if *len < reg_data.len() as u32 || data.is_null() {
                    *len = reg_data.len() as u32;
                    return 0;
                }
                std::ptr::copy_nonoverlapping(reg_data.as_mut_ptr(), data, reg_data.len());
                *len = reg_data.len() as u32;
            }
            return 0;
        }
        Err(e) => {
            dbg!(e);
            return 2;
        }
    }
}

#[no_mangle]
pub extern "C" fn DeleteRegistryValue(
    key: HKEY,
    sub_key: *const c_char,
    value_name: *const c_char,
) -> u32 {
    if key == HKEY::default() || sub_key.is_null() {
        return 1;
    }
    let sub_key_vec16 = cstr_to_vec16(sub_key);
    let sub_key_pcwstr = PCWSTR::from_raw(sub_key_vec16.as_ptr());
    let value_name_vec16 = cstr_to_vec16(value_name);
    let value_name_pcwstr: PCWSTR;
    if value_name_vec16.len() == 1 {
        value_name_pcwstr = PCWSTR::null();
    } else {
        value_name_pcwstr = PCWSTR::from_raw(value_name_vec16.as_ptr());
    }

    let ret = delete_registry_value(key, sub_key_pcwstr, value_name_pcwstr);
    match ret {
        Ok(_) => {
            return 0;
        }
        Err(e) => {
            dbg!(e);
            return 2;
        }
    }
}

#[no_mangle]
pub extern "C" fn GetFileSignerName(file_path: *const c_char, name: *mut u8, len: *mut u32) -> u32 {
    if file_path.is_null() || len.is_null() {
        return 1;
    }
    let file_path_vec16 = cstr_to_vec16(file_path);
    let file_path_pcwstr = PCWSTR::from_raw(file_path_vec16.as_ptr());
    let ret = get_file_signer_name(file_path_pcwstr);
    match ret {
        Ok(sign_name) => {
            unsafe {
                if *len < sign_name.len() as u32 || name.is_null() {
                    *len = sign_name.len() as u32;
                    return 0;
                }
                std::ptr::copy_nonoverlapping(sign_name.as_bytes().as_ptr(), name, sign_name.len());
                *len = sign_name.len() as u32;
            }
            return 0;
        }
        Err(_e) => {
            return 2;
        }
    }
}

#[no_mangle]
pub extern "C" fn GetFileVersionValue(
    value_name: *const c_char,
    module_name: *const c_char,
    value: *mut u8,
    len: *mut u32,
) -> u32 {
    if value_name.is_null() || module_name.is_null() || len.is_null() {
        return 1;
    }
    let value_name_vec16 = cstr_to_vec16(value_name);
    let value_name_pcwstr = PCWSTR::from_raw(value_name_vec16.as_ptr());
    let module_name_vec16 = cstr_to_vec16(module_name);
    let module_name_pcwstr = PCWSTR::from_raw(module_name_vec16.as_ptr());
    let ret = get_file_version_info(value_name_pcwstr, module_name_pcwstr);
    match ret {
        Ok(value_str) => {
            unsafe {
                if *len < value_str.len() as u32 || value.is_null() {
                    *len = value_str.len() as u32;
                    return 0;
                }
                std::ptr::copy_nonoverlapping(
                    value_str.as_bytes().as_ptr(),
                    value,
                    value_str.len(),
                );
                *len = value_str.len() as u32;
            }
            return 0;
        }
        Err(_e) => {
            return 2;
        }
    }
}

#[no_mangle]
pub extern "C" fn ExecWmi(
    class_name: *const c_char,
    condition: *const c_char,
    namespace: *const c_char,
    key: *const c_char,
    value: *mut u8,
    len: *mut u32,
) -> u32 {
    if class_name.is_null() || namespace.is_null() || key.is_null() || len.is_null() {
        return 1;
    }
    let class_name_str = cstr_to_str(class_name);
    let condition_str = cstr_to_str(condition);
    let namespace_str = cstr_to_str(namespace);
    let key_str = cstr_to_str(key);
    let keys = [key_str; 1];
    let ret = exec_wmi(class_name_str, condition_str, namespace_str, &keys);
    match ret {
        Ok(hashmap) => unsafe {
            let value_opt = hashmap.get(key_str.into());
            if let Some(value_ret) = value_opt {
                if *len < value_ret.len() as u32 || value.is_null() {
                    *len = value_ret.len() as u32;
                    return 0;
                }
                std::ptr::copy_nonoverlapping(
                    value_ret.as_bytes().as_ptr(),
                    value,
                    value_ret.len(),
                );
                *len = value_ret.len() as u32;
                return 0;
            } else {
                return 2;
            }
        },
        Err(_e) => {
            return 3;
        }
    }
}

fn cstr_to_vec16(cstr: *const c_char) -> Vec<u16> {
    if cstr.is_null() {
        return Vec::default();
    }
    // dbg!(cstr);
    let cstr_slice = unsafe { CStr::from_ptr(cstr) };
    // dbg!(cstr_slice);
    // let cstr_bytes = cstr_slice.to_bytes();
    let cstr_str = String::from(cstr_slice.to_str().unwrap());
    // dbg!(&cstr_str);
    if cstr_str.is_empty() {
        return Vec::default();
    }
    let mut cstr_vec = cstr_str.encode_utf16().collect::<Vec<_>>();
    cstr_vec.push(0);
    cstr_vec
}

fn cstr_to_str(cstr: *const c_char) -> &'static str {
    if cstr.is_null() {
        return "";
    }
    let c_str: &CStr = unsafe { CStr::from_ptr(cstr) };
    c_str.to_str().unwrap()
}

#[allow(unused)]
#[no_mangle]
pub extern "stdcall" fn DllMain(inst: isize, reason: u32, _: *const u8) -> u32 {
    match reason {
        dll_process_attach => unsafe {
            DisableThreadLibraryCalls(HMODULE(inst));
        },
        dll_process_detach => {}
    }
    1
}
