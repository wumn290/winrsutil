use super::*;
use std::mem::size_of;

pub(crate) fn get_module_list(pid: u32) -> StdResult<Vec<MODULEENTRY32>, Box<dyn StdError>> {
    unsafe {
        if pid == 0 {
            return Err(WRUE::new(8, "Process".into(), "pid is 0".into()).into());
        }
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)?;
        let _p = Defer(move ||{let _ = CloseHandle(snap);()});
        let mut me32 = MODULEENTRY32::default();
        me32.dwSize = size_of::<MODULEENTRY32>() as u32;
        let _ = Module32First(snap, &mut me32)?;
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)?;
        let _p = Defer(move || {let _ = CloseHandle(process_handle);});
        let mut vc_ret = Vec::new();
        loop {
            vc_ret.push(me32);
            let ret = Module32Next(snap, &mut me32);
            if let Err(_) = ret {
                break;
            }
        }
        Ok(vc_ret)
    }
}
