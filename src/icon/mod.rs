use std::ffi::c_void;
use std::mem::size_of;
use std::ops::Index;
use windows::{
    core::*, Win32::Foundation::*, Win32::Graphics::Gdi::*, Win32::Storage::FileSystem::*,
    Win32::UI::WindowsAndMessaging::*,
};

use common::*;

#[derive(Default)]
#[repr(C, packed)]
struct ICONHEADER(u16, u16, u16);

#[derive(Default)]
#[repr(C, packed)]
struct ICONDIR(u8, u8, u8, u8, u16, u16, u32, u32);

pub fn save_exe_icon(file_name: PCWSTR, icon_path: PCWSTR) -> StdResult<(), Box<dyn StdError>> {
    if file_name.is_null() || icon_path.is_null() {
        return Err(WRUE::new(1, "Icon".into(), "file_name or icon_path is invalid".into()).into());
    }
    unsafe {
        dbg!(
            file_name.to_string().unwrap_unchecked(),
            icon_path.to_string().unwrap_unchecked()
        );
    }
    const ICON_COUNT: u32 = 1_u32;
    let mut hicon_default = vec![HICON::default(); ICON_COUNT as usize];
    let mut ids_default = 0_u32;
    let mut file_name_vec = vec![0_u16; MAX_PATH as usize];

    unsafe {
        file_name.as_wide().iter().enumerate().for_each(|(i, e)| {
            file_name_vec[i] = *e;
        });
        let icons = PrivateExtractIconsW(
            file_name_vec[..].try_into().unwrap(),
            0,
            128,
            128,
            Some(&mut hicon_default),
            Some(&mut ids_default),
            0,
        );
        if icons <= 0 {
            return Err(WRUE::new(2, "Icon".into(), "extract icon failed".into()).into());
        }
        let hfile = CreateFileW(
            icon_path,
            GENERIC_WRITE.0,
            FILE_SHARE_MODE::default(),
            None,
            CREATE_ALWAYS,
            FILE_FLAGS_AND_ATTRIBUTES::default(),
            HANDLE::default(),
        )?;
        write_icon_header(hfile, ICON_COUNT as i32)?;
        SetFilePointer(hfile, size_of::<ICONDIR>() as i32, None, FILE_CURRENT);
        let mut image_offsets = vec![0_u32; ICON_COUNT as usize];
        for i in 0..ICON_COUNT {
            let mut icon_info = ICONINFO::default();
            let (mut bmp_color, mut bmp_mask) = (BITMAP::default(), BITMAP::default());
            get_icon_bitmap_info(
                &(hicon_default.index(i as usize)),
                &mut icon_info as *mut ICONINFO,
                &mut bmp_color as *mut BITMAP,
                &mut bmp_mask as *mut BITMAP,
            )?;
            image_offsets[i as usize] = SetFilePointer(hfile, 0, None, FILE_CURRENT);
            wrire_icon_image_header(hfile, &mut bmp_color, &mut bmp_mask)?;
            write_icon_data(hfile, &icon_info.hbmColor)?;
            write_icon_data(hfile, &icon_info.hbmMask)?;
            DeleteObject(icon_info.hbmColor);
            DeleteObject(icon_info.hbmMask);
        }
        SetFilePointer(hfile, size_of::<ICONHEADER>() as i32, None, FILE_BEGIN);
        for i in 0..ICON_COUNT {
            write_icon_directory_entry(
                hfile,
                i as i32,
                &hicon_default[i as usize],
                image_offsets[i as usize],
            )?;
        }
        CloseHandle(hfile)?;
    }
    Ok(())
}

fn write_icon_header(hfile: HANDLE, icon_count: i32) -> StdResult<(), Box<dyn StdError>> {
    if hfile.is_invalid() || icon_count <= 0 {
        return Err(WRUE::new(3, "Icon".into(), "write icon header failed".into()).into());
    }
    let icon_header = ICONHEADER(0, 1, icon_count as u16);

    let mut write_bytes = 0_u32;
    unsafe {
        let ico_slice = std::slice::from_raw_parts(
            &icon_header as *const ICONHEADER as *const u8,
            size_of::<ICONHEADER>(),
        );
        let _ret = WriteFile(
            hfile,
            Some(ico_slice),
            Some(&mut write_bytes as *mut u32),
            None,
        )?;
    }
    Ok(())
}

fn get_icon_bitmap_info(
    hicon: &HICON,
    picon_info: *mut ICONINFO,
    pbmp_color: *mut BITMAP,
    pbmp_mask: *mut BITMAP,
) -> StdResult<(), Box<dyn StdError>> {
    if hicon.is_invalid() || picon_info.is_null() || pbmp_color.is_null() || pbmp_mask.is_null() {
        return Err(WRUE::new(4, "Icon".into(), "get icon bitmap info failed".into()).into());
    }
    unsafe {
        GetIconInfo(*hicon, picon_info)?;
        let ret = GetObjectW(
            (*picon_info).hbmColor,
            size_of::<BITMAP>() as i32,
            Some(pbmp_color as *mut c_void),
        );
        if ret == 0 {
            return Err(Error::new(HRESULT(12), "get icon bitmap color failed".into()).into());
        }
        let ret = GetObjectW(
            (*picon_info).hbmMask,
            size_of::<BITMAP>() as i32,
            Some(pbmp_mask as *mut c_void),
        );
        if ret == 0 {
            return Err(WRUE::new(5, "Icon".into(), "get icon bitmap color failed".into()).into());
        }
    }
    Ok(())
}

fn wrire_icon_image_header(
    hfile: HANDLE,
    pbmp_color: *mut BITMAP,
    pbmp_mask: *mut BITMAP,
) -> StdResult<(), Box<dyn StdError>> {
    if hfile.is_invalid() || pbmp_color.is_null() || pbmp_mask.is_null() {
        return Err(WRUE::new(6, "Icon".into(), "write icon image header failed".into()).into());
    }
    let mut header = BITMAPINFOHEADER::default();
    let mut write_bytes: u32 = 0;
    let image_bytes: u32 = calc_bitmap_bytes(pbmp_color) + calc_bitmap_bytes(pbmp_mask);
    unsafe {
        header.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        header.biWidth = (*pbmp_color).bmWidth;
        header.biHeight = (*pbmp_color).bmHeight * 2;
        header.biPlanes = (*pbmp_color).bmPlanes;
        header.biBitCount = (*pbmp_color).bmBitsPixel;
        header.biSizeImage = image_bytes;
        let header_slice = std::slice::from_raw_parts(
            &header as *const BITMAPINFOHEADER as *const u8,
            size_of::<BITMAPINFOHEADER>(),
        );
        WriteFile(hfile, Some(header_slice), Some(&mut write_bytes), None)?;
    }
    Ok(())
}

fn calc_bitmap_bytes(pbitmap: *mut BITMAP) -> u32 {
    if pbitmap.is_null() {
        return 0;
    }
    unsafe {
        let mut width_biyes = (*pbitmap).bmWidthBytes;
        if (width_biyes & 3) != 0 {
            width_biyes = (width_biyes + 4) & !3;
        }
        (width_biyes * (*pbitmap).bmHeight) as u32
    }
}

fn write_icon_data(hfile: HANDLE, hbitmap: &HBITMAP) -> StdResult<(), Box<dyn StdError>> {
    if hfile.is_invalid() || hbitmap.is_invalid() {
        return Err(WRUE::new(7, "Icon".into(), "write icon data failed".into()).into());
    }
    let mut bmp = BITMAP::default();
    unsafe {
        GetObjectW(
            HGDIOBJ(hbitmap.0),
            size_of::<BITMAP>() as i32,
            Some(&mut bmp as *mut BITMAP as *mut c_void),
        );
        let bitmap_bytes = calc_bitmap_bytes(&mut bmp);
        let mut info_data = vec![0_u8; bitmap_bytes as usize];
        GetBitmapBits(
            *hbitmap,
            bitmap_bytes as i32,
            info_data.as_mut_ptr() as *mut c_void,
        );
        for i in (0..bmp.bmHeight).rev() {
            let write_slice = std::slice::from_raw_parts(
                (info_data.as_mut_ptr() as *mut u8).offset((i * bmp.bmWidthBytes) as isize),
                bmp.bmWidthBytes as usize,
            );
            let mut writeten = 0_u32;
            WriteFile(
                hfile,
                Some(write_slice),
                Some(&mut writeten), // 1 line of BYTES
                None,
            )?;
            if bmp.bmWidthBytes & 3 != 0 {
                let padding = vec![0_u8; (4 - bmp.bmWidthBytes) as usize];
                WriteFile(hfile, Some(&padding[..]), Some(&mut writeten), None)?;
            }
        }
    }
    Ok(())
}

fn write_icon_directory_entry(
    hfile: HANDLE,
    _: i32,
    hicon: &HICON,
    offset: u32,
) -> StdResult<(), Box<dyn StdError>> {
    if hfile.is_invalid() || hicon.is_invalid() {
        return Err(WRUE::new(8, "Icon".into(), "write icon directory entry failed".into()).into());
    }
    unsafe {
        let mut icon_info = ICONINFO::default();
        let mut icon_dir = ICONDIR::default();
        let mut bmp_color = BITMAP::default();
        let mut bmp_mask = BITMAP::default();
        get_icon_bitmap_info(hicon, &mut icon_info, &mut bmp_color, &mut bmp_mask)?;
        let image_bytes = calc_bitmap_bytes(&mut bmp_color) + calc_bitmap_bytes(&mut bmp_mask);
        let color_count: u32;
        if bmp_color.bmBitsPixel >= 8 {
            color_count = 0;
        } else {
            color_count = 1 << (bmp_color.bmBitsPixel * bmp_color.bmPlanes);
        }
        icon_dir.0 = bmp_color.bmWidth as u8;
        icon_dir.1 = bmp_color.bmHeight as u8;
        icon_dir.2 = color_count as u8;
        icon_dir.3 = 0;
        icon_dir.4 = bmp_color.bmPlanes;
        icon_dir.5 = bmp_color.bmBitsPixel;
        icon_dir.6 = size_of::<BITMAPINFOHEADER>() as u32 + image_bytes;
        icon_dir.7 = offset;
        let write_slice = std::slice::from_raw_parts(
            &mut icon_dir as *mut ICONDIR as *mut u8,
            size_of::<ICONDIR>(),
        );
        let mut written = 0_u32;
        WriteFile(hfile, Some(write_slice), Some(&mut written), None)?;
        DeleteObject(icon_info.hbmColor);
        DeleteObject(icon_info.hbmMask);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon() {
        let ret = save_exe_icon(
            w!("C:\\Windows\\System32\\cmd.exe"),
            w!("C:\\Users\\Admin\\AppData\\Local\\Temp\\winrsutil_rust_test184341.ico"),
        );
        dbg!(&ret);
        assert_eq!(ret.is_ok(), true);
    }
}
