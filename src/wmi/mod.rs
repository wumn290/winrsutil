use super::*;
use std::collections::*;
use windows::{
    core::*, Win32::Foundation::*, Win32::System::Com::*, Win32::System::Ole::*,
    Win32::System::Variant::*, Win32::System::Wmi::*,
};

pub(crate) fn exec_wmi(
    class_name: &str,
    condition: &str,
    namespace: &str,
    keys: &[&str],
) -> StdResult<HashMap<String, String>, Box<dyn StdError>> {
    if class_name.is_empty() || keys.is_empty() || namespace.is_empty() {
        return Err(WRUE::new(
            1,
            "Wmi".into(),
            "class_name or namespace or keys is invalid".into(),
        )
        .into());
    }
    let kets_str = keys.join(", ");
    let mut wql_str = format!("select {} from {}", kets_str, class_name);
    if !condition.is_empty() {
        wql_str += " where ";
        wql_str += condition;
    }
    let mut results = HashMap::new();
    unsafe {
        let ret = CoInitializeEx(None, COINIT_MULTITHREADED);
        if let Err(e) = ret {
            if e.code() == RPC_E_TOO_LATE {
                println!("call CoInitializeEx failed: {}", e.message());
            } else {
                return Err(e.into());
            }
        }
        let ret = CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        );
        if let Err(e) = ret {
            if e.code() == RPC_E_TOO_LATE {
                println!("call CoInitializeSecurity failed: {}", e.message());
            } else {
                return Err(e.into());
            }
        }
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let server =
            locator.ConnectServer(&BSTR::from(namespace), None, None, None, 0, None, None)?;
        let query = server.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(wql_str),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;
        loop {
            let mut row = [None; 1];
            let mut returned = 0;
            query.Next(WBEM_INFINITE, &mut row, &mut returned).ok()?;
            if let Some(row) = &row[0] {
                for key in keys {
                    let mut key_vec16 = key.encode_utf16().collect::<Vec<_>>();
                    key_vec16.push(0u16);
                    let key_utf16 = PCWSTR::from_raw(key_vec16.as_ptr());
                    let mut value: VARIANT = Default::default();
                    let ret = row.Get(key_utf16, 0, &mut value, None, None);
                    match ret {
                        Ok(_) => {
                            let var_str = VarFormat(
                                &value,
                                None,
                                VARFORMAT_FIRST_DAY_SYSTEMDEFAULT,
                                VARFORMAT_FIRST_WEEK_SYSTEMDEFAULT,
                                0,
                            )
                            .unwrap_or(BSTR::from("error"));
                            println!("{}", var_str);
                            // let value_str = format
                            results.insert(String::from(*key), var_str.to_string());
                            // TODO: workaround for https://github.com/microsoft/windows-rs/issues/539
                            let _ret = VariantClear(&mut value);
                        }
                        Err(_e) => {
                            continue;
                        }
                    }
                }
            } else {
                break;
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wmi() {
        let ret = exec_wmi(
            "Win32_ComputerSystem",
            "",
            "root\\cimv2",
            &["Manufacturer", "Model", "OEMStringArray"][..],
        );
        dbg!(&ret);
        let ret = exec_wmi("Win32_Processor", "", "root\\cimv2", &["AddressWidth"][..]);
        dbg!(&ret);
    }
}
