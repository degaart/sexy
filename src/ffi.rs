use anyhow::{bail, Result};
use std::{ffi::CString, os::raw::c_char, path::Path};

#[cfg(windows)]
use std::{ffi::OsString, cell::RefCell};

pub struct StrConverter {
    data: CString,
}

impl StrConverter {
    pub fn new(s: impl AsRef<str>) -> Result<Self> {
        let data = CString::new(s.as_ref())?;
        Ok(Self { data })
    }

    pub fn as_c_char(&self) -> *const c_char {
        self.data.as_ptr() as *const c_char
    }
}

#[cfg(windows)]
pub struct WideString {
    data: OsString,
    wide: RefCell<Option<Vec<u16>>>,
}

#[cfg(windows)]
impl WideString {

    pub fn new(s: impl AsRef<str>) -> Self {
        Self {
            data: OsString::from(s.as_ref()),
            wide: RefCell::new(None),
        }
    }

    pub fn as_wide(&self) -> *const u16 {
        use std::os::windows::ffi::OsStrExt;
        if self.wide.borrow().is_none() {
            *self.wide.borrow_mut() = Some(self.data
                .encode_wide()
                .chain(Some(0)) // add NULL termination
                .collect::<Vec<u16>>());
        }
        self.wide.borrow().as_ref().unwrap().as_ptr()
    }

    pub fn to_str(&self) -> anyhow::Result<&str> {
        self.data
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid UTF-8 string"))
    }

}

#[cfg(windows)]
impl From<*const u16> for WideString {
    fn from(value: *const u16) -> Self {
        use std::os::windows::ffi::OsStringExt;
        unsafe {
            let length = (0..).take_while(|&i| *value.offset(i) != 0).count();
            let slice = std::slice::from_raw_parts(value, length);
            Self {
                data: OsString::from_wide(slice),
                wide: RefCell::new(None)
            }
        }
    }
}

pub struct PathConverter {
    data: CString,
}

impl PathConverter {
    pub fn new(s: impl AsRef<Path>) -> Result<Self> {
        let as_string = s.as_ref().to_str();
        if as_string.is_none() {
            bail!("Path contains invalid UTF-8 characters");
        }

        let data = CString::new(as_string.unwrap())?;
        Ok(Self { data })
    }

    pub fn as_c_char(&self) -> *const c_char {
        self.data.as_ptr() as *const c_char
    }
}
