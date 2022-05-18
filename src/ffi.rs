use std::{ffi::CString, os::raw::c_char, path::Path};
use anyhow::{Result, bail};

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

pub struct PathConverter {
    data: CString,
}

impl PathConverter {
    pub fn new(s: impl AsRef<Path>) -> Result<Self> {
        let as_string = s.as_ref().to_str();
        if let None = as_string {
            bail!("Path contains invalid UTF-8 characters");
        }

        let data = CString::new(as_string.unwrap())?;
        Ok(Self { data })
    }

    pub fn as_c_char(&self) -> *const c_char {
        self.data.as_ptr() as *const c_char
    }
}



