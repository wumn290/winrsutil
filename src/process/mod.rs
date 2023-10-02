use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::Diagnostics::ToolHelp::*,
    Win32::System::Threading::*,
    Win32::System::ProcessStatus::*,
    Win32::Storage::FileSystem::*,
    Wdk::System::Threading::*,
    Win32::System::Diagnostics::Debug::*
};
use std::ffi::c_void;
use super::*;
use std::mem::size_of;
mod module;
use module::*;

pub(crate) const PEOCESS_BASE_INFO: PROCESS_INFO_FLAGS = PROCESS_INFO_FLAGS(1_u32);
pub(crate) const PEOCESS_DETAIL_INFO: PROCESS_INFO_FLAGS = PROCESS_INFO_FLAGS(2_u32);
pub(crate) const PEOCESS_MODULE_INFO: PROCESS_INFO_FLAGS = PROCESS_INFO_FLAGS(4_u32);
#[derive(::core::cmp::PartialEq, ::core::cmp::Eq)]
pub(crate) struct PROCESS_INFO_FLAGS(pub(crate) u32);
impl ::core::marker::Copy for PROCESS_INFO_FLAGS {}
impl ::core::clone::Clone for PROCESS_INFO_FLAGS {
    fn clone(&self) -> Self {
        *self
    }
}
impl ::core::default::Default for PROCESS_INFO_FLAGS {
    fn default() -> Self {
        Self(0)
    }
}
impl TypeKind for PROCESS_INFO_FLAGS {
    type TypeKind = CopyType;
}
impl ::core::fmt::Debug for PROCESS_INFO_FLAGS {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_tuple("PROCESS_INFO_FLAGS").field(&self.0).finish()
    }
}

impl ::core::ops::BitOr for PROCESS_INFO_FLAGS {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl ::core::ops::BitAnd for PROCESS_INFO_FLAGS {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}
impl ::core::ops::BitOrAssign for PROCESS_INFO_FLAGS {
    fn bitor_assign(&mut self, other: Self) {
        self.0.bitor_assign(other.0)
    }
}
impl ::core::ops::BitAndAssign for PROCESS_INFO_FLAGS {
    fn bitand_assign(&mut self, other: Self) {
        self.0.bitand_assign(other.0)
    }
}
impl ::core::ops::Not for PROCESS_INFO_FLAGS {
    type Output = Self;
    fn not(self) -> Self {
        Self(self.0.not())
    }
}

#[derive(::core::cmp::PartialEq, ::core::cmp::Eq)]
pub(crate) struct PROCESS_INFO {
    pub(crate) base: PROCESSENTRY32,
    pub(crate) path: String,
    pub(crate) cmdline: String,
    pub(crate) createtime: FILETIME,
    pub(crate) modules: Vec<MODULEENTRY32>,
}

impl ::core::default::Default for PROCESS_INFO {
    fn default() -> Self {
        Self{
            base: PROCESSENTRY32::default(),
            path: String::default(),
            cmdline: String::default(),
            createtime: FILETIME::default(),
            modules: Vec::default(),
        }
    }
}

impl ::core::fmt::Debug for PROCESS_INFO {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        f.debug_struct("PROCESS_INFO").field("base", &self.base.th32ProcessID).field("path", &self.path).field("cmdline", &self.cmdline).field("createtime", &self.createtime).field("modules", &self.modules).finish()
    }
}

pub(crate) fn get_process_list(flags: PROCESS_INFO_FLAGS) -> StdResult<Vec<PROCESS_INFO>, Box<dyn StdError>> {
    unsafe {
        if flags == PROCESS_INFO_FLAGS::default() {
            return Err(WRUE::new(9, "Process".into(), "flags is 0".into()).into());
        }
        let snap_shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0)?;
        let _p = Defer(move || {let _ = CloseHandle(snap_shot);});
        let mut pe32: PROCESSENTRY32 = PROCESSENTRY32::default();
        pe32.dwSize = size_of::<PROCESSENTRY32>() as u32;
        Process32First(snap_shot, &mut pe32 as *mut PROCESSENTRY32)?;
        let mut vec_ret = Vec::new();
        loop {
            let mut proc_info = PROCESS_INFO::default();
            // let cstr_slice = CStr::from_ptr(pe32.szExeFile.as_ptr() as *const i8);
            // let cstr_str = String::from(cstr_slice.to_str().unwrap_or("".into()));
            if (flags & PEOCESS_DETAIL_INFO) == PEOCESS_DETAIL_INFO {
                let path_ret = get_process_full_path(pe32.th32ProcessID);
                if let Ok(path) = path_ret {
                    proc_info.path = path;
                }
                let ret = get_process_commandline(pe32.th32ProcessID);
                if let Ok(cmdline) = ret {
                    proc_info.cmdline = cmdline
                }
                let create_time_ret = get_process_create_time(pe32.th32ProcessID);
                if let Ok(create_time) = create_time_ret {
                    proc_info.createtime = create_time
                }
            }
            if (flags & PEOCESS_MODULE_INFO) == PEOCESS_MODULE_INFO {
                let module_ret = get_module_list(pe32.th32ProcessID);
                if let Ok(module_vec) = module_ret {
                    proc_info.modules = module_vec;
                }
            }
            // println!("{}, {}", cstr_str, pe32.th32ProcessID);
            if (flags & PEOCESS_BASE_INFO) == PEOCESS_BASE_INFO {
                proc_info.base = pe32;
            }
            vec_ret.push(proc_info);
            let ret = Process32Next(snap_shot, &mut pe32 as *mut PROCESSENTRY32);
            if let Err(_) = ret {
                break;
            }
        }
        Ok(vec_ret)
    }
}

fn get_process_full_path(pid: u32) -> StdResult<String, Box<dyn StdError>> {
    unsafe {
        if pid == 0 {
            return Err(WRUE::new(1, "Process".into(), "pid is 0".into()).into());
        }
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)?;
        let _p = Defer(move || {let _ = CloseHandle(process_handle);});
        let mut image_path = vec![0_u16; MAX_PATH as usize];
        let ret = GetProcessImageFileNameW(
            process_handle,
            image_path.as_mut_slice()
        );
        if 0 == ret {
            return  Err(Error::from_win32().into());
        }
        let ret = dospath_to_ntpath(PCWSTR::from_raw(image_path.as_ptr()).to_string().unwrap_or("".into()));
        match ret {
            Ok(str) => {
                return Ok(str);
            },
            Err(e) => {
                return  Err(e);
            }
        }
    }
}

fn dospath_to_ntpath(dos_path: String) -> StdResult<String, Box<dyn StdError>> {
    if dos_path.is_empty() {
        return Err(WRUE::new(2, "Process".into(), "dos_path is empty".into()).into());
    }
    unsafe {
        let mut drivestr = vec![0_u16; MAX_PATH as usize];
        let ret = GetLogicalDriveStringsW( Some(drivestr.as_mut_slice()));
        if ret == 0 {
            return  Err(Error::from_win32().into());
        }
        let drivestr_slice = drivestr.as_mut_slice();
        let drive_param= &mut vec![0_u16;3][..];
        let mut dev_name = vec![0_u16;100];
        let dev_name = dev_name.as_mut_slice();
        let drivestrs = drivestr_slice.split(|c| *c == '\0' as u16);
        for v in drivestrs {
            if v.len() < 2 {
                continue;
            }
            let mut str_deive = PCWSTR::from_raw(v.as_ptr()).to_string().unwrap_or("".into());
            if str_deive == "A:\\" || str_deive == "B:\\" {
                continue;
            }
            drive_param[0] = v[0].clone();
            drive_param[1] = v[1].clone();
            drive_param[2] = 0_u16;
            let ret = QueryDosDeviceW(PCWSTR::from_raw(drive_param.as_ptr()), Some(dev_name));
            if ret == 0 {
                return Err(Error::from_win32().into());
            }
            let target_str = PCWSTR::from_raw(dev_name.as_ptr()).to_string().unwrap_or("".into());
            let target_str = target_str.to_string();
            str_deive = str_deive.trim_end_matches('\\').into();
            if dos_path.find(&target_str).is_some() {
                return Ok(dos_path.replace(&target_str, &str_deive));
            }
        }
    }
    Err(WRUE::new(3, "Process".into(), "get nt path failed".into()).into())
}

fn get_process_commandline(pid: u32) -> StdResult<String, Box<dyn StdError>> {
    if pid == 0 {
        return Err(WRUE::new(4, "Process".into(), "pid is 0".into()).into());
    }
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)?;
        let _p = Defer(move || {let _ = CloseHandle(process_handle);()});
        let mut pbi:  PROCESS_BASIC_INFORMATION =  PROCESS_BASIC_INFORMATION::default();
        let mut query_len: u32 = 0;
        let query_ret = NtQueryInformationProcess(process_handle, ProcessBasicInformation, &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
        size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut query_len as *mut u32);
        if let Err(e) = query_ret {
            return Err(e.into());
        }
        if pbi.PebBaseAddress.is_null() {
            return Err(WRUE::new(6, "Process".into(), "PebBaseAddress is 0".into()).into());
        }
        let mut peb: PEB = PEB::default();
        let mut dumy: usize = 0;
        let ret_read1 = ReadProcessMemory(process_handle, pbi.PebBaseAddress as *const c_void, &mut peb as *mut PEB as *mut c_void, size_of::<PEB>(),
        Some(&mut dumy as *mut usize));
        if let Err(e) = ret_read1 {
            return Err(e.into());
        }
        let mut param = RTL_USER_PROCESS_PARAMETERS::default();
        let ret_read2 = ReadProcessMemory(process_handle, peb.ProcessParameters as *const c_void, &mut param as *mut RTL_USER_PROCESS_PARAMETERS as *mut c_void,
            size_of::<RTL_USER_PROCESS_PARAMETERS>(), Some(&mut dumy as *mut usize));
        if let Err(e) = ret_read2 {
            return Err(e.into());
        }
        let address = param.ImagePathName.Buffer;
        let size = param.ImagePathName.Length;
        let mut buffer = vec![0_u16; size as usize / size_of::<u16>() + 1];
        let ret_read3 = ReadProcessMemory(process_handle, address.as_ptr() as *const c_void, buffer.as_mut_ptr() as *mut c_void, size as usize + 1, Some(&mut dumy as *mut usize));
        if let Err(e) = ret_read3 {
            return Err(e.into());
        }
        buffer.push(0_u16);
        let image_path = PCWSTR::from_raw(buffer.as_ptr()).to_string();
        let image_path = image_path.unwrap_or("".into());
        // println!("image_path={}", image_path);

        let address = param.CommandLine.Buffer;
        let size = param.CommandLine.Length;
        let mut buffer = vec![0_u16; size as usize / size_of::<u16>() + 1];
        let ret_read4 = ReadProcessMemory(process_handle, address.as_ptr() as *const c_void, buffer.as_mut_ptr() as *mut c_void, size as usize + 1, Some(&mut dumy as *mut usize));
        if let Err(e) = ret_read4 {
            return Err(e.into());
        }
        buffer.push(0_u16);
        let cmdline = PCWSTR::from_raw(buffer.as_ptr()).to_string();
        let cmdline = cmdline.unwrap_or("".into());
        // println!("cmdline={}", cmdline);
        Ok(cmdline)
    }
}

fn get_process_create_time(pid: u32) -> StdResult<FILETIME, Box<dyn StdError>> {
    unsafe {
        if pid == 0 {
            return Err(WRUE::new(7, "Process".into(), "pid is 0".into()).into());
        }
        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)?;
        let _p = Defer(move || {let _ = CloseHandle(process_handle);()});
        let mut create_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();
        GetProcessTimes(process_handle, &mut create_time, &mut exit_time,&mut kernel_time,&mut user_time)?;
        // println!("create_time={:?}, exit_time={:?}, kernel_time={:?}, user_time={:?}", create_time, exit_time, kernel_time, user_time);
        Ok(create_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_process() {
        let vec_ret = get_process_list(PEOCESS_BASE_INFO | PEOCESS_DETAIL_INFO);
        assert_eq!(vec_ret.is_ok(), true);
        // dbg!(&vec_ret);
    }

}
