use common::*;
use std::ffi::c_void;
use std::mem::size_of;
use windows::{
    core::*, Win32::Foundation::*, Win32::Security::Cryptography::*, Win32::Security::WinTrust::*,
};

pub fn get_file_signer_name(file_path: PCWSTR) -> StdResult<String, Box<dyn StdError>> {
    if file_path.is_null() {
        return Err(WRUE::new(1, "Sign".into(), "file_path is null".into()).into());
    }
    dbg!(file_path.to_owned());
    let mut file_data = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: file_path,
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_data as *mut WINTRUST_FILE_INFO,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS::default(),
        ..Default::default()
    };
    let mut policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    unsafe {
        let status = WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut policy_guid as *mut GUID,
            &mut win_trust_data as *mut WINTRUST_DATA as *mut c_void,
        );
        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            HWND(INVALID_HANDLE_VALUE.0),
            &mut policy_guid as *mut GUID,
            &mut win_trust_data as *mut WINTRUST_DATA as *mut c_void,
        );
        if status != ERROR_SUCCESS.0 as i32 && status != CERT_E_EXPIRED.0 {
            return Err(WRUE::new(2, "Sign".into(), "verify trust failed".into()).into());
        }
        let (mut pstore, mut pmsg): (HCERTSTORE, *mut c_void) =
            (HCERTSTORE(std::ptr::null_mut()), std::ptr::null_mut());
        let _ = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            file_path.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_ALL,
            CERT_QUERY_FORMAT_FLAG_ALL,
            0,
            None,
            None,
            None,
            Some(&mut pstore as *mut HCERTSTORE),
            Some(&mut pmsg as *mut *mut c_void),
            None,
        )?;
        if pstore.is_invalid() || pmsg == std::ptr::null_mut() {
            return Err(WRUE::new(3, "Sign".into(), "crypto query object failed".into()).into());
        }
        let mut len: u32 = 0_u32;
        let _ = CryptMsgGetParam(pmsg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut len as *mut u32)?;
        if len == 0 {
            return Err(WRUE::new(4, "Sign".into(), "crypto get msg len failed".into()).into());
        }
        let mut signer_info = vec![0_u8; len as usize];
        let _ = CryptMsgGetParam(
            pmsg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_info.as_mut_ptr() as *mut c_void),
            &mut len as *mut u32,
        )?;
        let signer_info = signer_info.as_ptr() as *const CMSG_SIGNER_INFO;
        let cert_info = CERT_INFO {
            Issuer: (*signer_info).Issuer,
            SerialNumber: (*signer_info).SerialNumber,
            ..Default::default()
        };
        let cert_context = CertFindCertificateInStore(
            pstore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const CERT_INFO as *const c_void),
            None,
        );
        if cert_context == std::ptr::null_mut() {
            return Err(
                WRUE::new(5, "Sign".into(), "find certificate in store failed".into()).into(),
            );
        }
        let len = CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        if len == 0 {
            return Err(
                WRUE::new(6, "Sign".into(), "cert get name string len failed".into()).into(),
            );
        }
        let buf = vec![0_u16; len as usize + 1];
        let buf_slice = std::slice::from_raw_parts_mut(
            buf.as_ptr() as *mut u16,
            (len as usize + 1) * size_of::<u16>(),
        );
        let res = CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(buf_slice),
        );
        if res == 0 {
            return Err(WRUE::new(7, "Sign".into(), "cert get name string failed".into()).into());
        }
        Ok(PCWSTR::from_raw(buf.as_ptr() as *const u16)
            .to_string()
            .unwrap_or(String::from("")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer() {
        let ret = get_file_signer_name(w!("C:\\Windows\\explorer.exe"));
        dbg!(&ret);
        assert_ne!(ret.unwrap_or(String::from("")), String::from(""));
    }
}
