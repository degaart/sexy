pub mod ffi;

pub use log::LevelFilter;

use anyhow::bail;
use log::info;
use std::{
    borrow::Cow,
    ffi::{c_char, CStr, CString},
    io::{self, Error, Write},
    mem,
    path::Path,
    ptr,
};

#[cfg(windows)]
use std::ffi::OsString;

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "mail")]
pub mod mail;

#[macro_export]
macro_rules! regex {
    ($re:literal $(,)?) => {{
        static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
        RE.get_or_init(|| regex::Regex::new($re).unwrap())
    }};

    ($re:expr) => {{
        static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
        RE.get_or_init(|| regex::Regex::new($re).unwrap())
    }};
}

pub struct LoggerBuilder {
    show_source: bool,
    level: LevelFilter,
    log_exit: bool,
    date_format: String,
}

impl Default for LoggerBuilder {
    fn default() -> Self {
        let show_source = cfg!(debug_assertions);
        let level = if cfg!(debug_assertions) {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        };
        Self {
            show_source,
            level,
            log_exit: true,
            date_format: String::from("%Y-%m-%d %H:%M:%S"),
        }
    }
}

impl LoggerBuilder {
    pub fn show_source(mut self, show: bool) -> Self {
        self.show_source = show;
        self
    }

    pub fn level(mut self, level: LevelFilter) -> Self {
        self.level = level;
        self
    }

    pub fn log_exit(mut self, log: bool) -> Self {
        self.log_exit = log;
        self
    }

    pub fn date_format(mut self, format: &str) -> Self {
        self.date_format = format.to_string();
        self
    }

    pub fn build(self) -> Logger {
        env_logger::builder()
            .filter_level(self.level)
            .format(move |buf, record| {
                let ts = format_date(
                    unsafe { libc::time(ptr::null_mut()) as u64 },
                    &self.date_format,
                );
                let ts = match ts {
                    Ok(ts) => ts,
                    Err(_) => "".to_string(),
                };
                if self.show_source {
                    let file = Path::new(record.file().unwrap_or(""));
                    writeln!(
                        buf,
                        "[{}][{}][{}:{}:{}] {}",
                        ts,
                        record.level(),
                        record.module_path().unwrap_or(""),
                        if let Some(name) = file.file_name() {
                            name.to_string_lossy()
                        } else {
                            Cow::from("")
                        },
                        record.line().unwrap_or(0),
                        record.args()
                    )
                } else {
                    writeln!(buf, "[{}][{}] {}", ts, record.level(), record.args())
                }
            })
            .init();
        Logger {
            log_exit: self.log_exit,
        }
    }
}

pub struct Logger {
    log_exit: bool,
}

impl Logger {
    pub fn builder() -> LoggerBuilder {
        LoggerBuilder::default()
    }

    pub fn level(&self, level: LevelFilter) {
        log::set_max_level(level);
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        if self.log_exit {
            info!("Exited");
        }
    }
}

#[deprecated]
pub fn init_logging() {
    let _ = Logger::builder().build();
}

pub struct LogExit {}

impl Drop for LogExit {
    fn drop(&mut self) {
        info!("Exited");
    }
}

extern "C" {
    fn strftime(
        buf: *mut c_char,
        maxsize: usize,
        format: *const c_char,
        timeptr: *mut libc::tm,
    ) -> usize;
}

pub fn parse_date(s: &str, fmt: &str) -> anyhow::Result<i64> {
    use chrono::{format::ParseErrorKind, DateTime, Local, NaiveDate, NaiveDateTime};
    match DateTime::parse_from_str(s, fmt) {
        Ok(dt) => Ok(dt.timestamp()),
        Err(e) => match e.kind() {
            ParseErrorKind::NotEnough => match NaiveDateTime::parse_from_str(s, fmt) {
                Ok(dt) => Ok(dt.timestamp()),
                Err(e) => match e.kind() {
                    ParseErrorKind::NotEnough => {
                        let dt = NaiveDate::parse_from_str(s, fmt)?
                            .and_hms_opt(0, 0, 0)
                            .ok_or_else(|| anyhow::anyhow!("Failed to parse date"))?
                            .and_local_timezone(Local)
                            .unwrap();
                        Ok(dt.timestamp())
                    }
                    _ => {
                        bail!(e);
                    }
                },
            },
            _ => {
                bail!(e);
            }
        },
    }
}

#[cfg(windows)]
pub fn localtime(timestamp: u64) -> Result<libc::tm, std::io::Error> {
    use libc::localtime_s;

    unsafe {
        let mut tm = mem::zeroed();
        let ts = timestamp as libc::time_t;
        if localtime_s(&mut tm, &ts) != 0 {
            Err(Error::last_os_error())
        } else {
            Ok(tm)
        }
    }
}

#[cfg(not(windows))]
pub fn localtime(timestamp: u64) -> Result<libc::tm, std::io::Error> {
    use libc::localtime_r;

    unsafe {
        let mut tm = mem::zeroed();
        if localtime_r(mem::transmute(&timestamp), &mut tm).is_null() {
            Err(Error::last_os_error())
        } else {
            Ok(tm)
        }
    }
}

pub fn format_date(timestamp: u64, fmt: &str) -> anyhow::Result<String> {
    let mut tm = localtime(timestamp)?;
    unsafe {
        let mut buffer = [08; 4096];
        let cfmt = CString::new(fmt)?;
        let ret = strftime(
            buffer.as_mut_ptr() as *mut c_char,
            buffer.len(),
            cfmt.as_ptr(),
            &mut tm,
        );
        if ret == 0 && fmt.len() > 0 {
            bail!("Failed to format time");
        }
        let result = CStr::from_ptr(buffer.as_ptr() as *const c_char).to_str()?;
        Ok(result.to_string())
    }
}

#[cfg(windows)]
pub unsafe fn string_from_lpcwstr(ptr: *const u16) -> OsString {
    use std::os::windows::ffi::OsStringExt;
    use winapi::um::winbase::lstrlenW;

    let len = lstrlenW(ptr) as usize;
    let slice = std::slice::from_raw_parts(ptr, len);

    OsString::from_wide(slice)
}

#[cfg(windows)]
pub fn last_win32_error() -> (u32, String) {
    use winapi::um::errhandlingapi::GetLastError;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winbase::{
        FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
    };

    unsafe {
        let last_error = GetLastError();
        let mut buffer: *mut u16 = ptr::null_mut();
        let ret = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            ptr::null_mut(),
            last_error,
            0,
            &mut buffer as *mut *mut u16 as *mut u16,
            512,
            ptr::null_mut(),
        );
        if ret == 0 {
            return (last_error, "Unknown error".to_string());
        }

        let s = string_from_lpcwstr(buffer);
        LocalFree(buffer as *mut libc::c_void);

        (last_error, s.to_string_lossy().into_owned())
    }
}

#[cfg(windows)]
pub fn disk_free_space(path: impl AsRef<Path>) -> Result<u64, io::Error> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::GetDiskFreeSpaceExW;

    let mut buf: Vec<u16> = path.as_ref().as_os_str().encode_wide().collect();
    buf.push(0);

    let mut free_space = 0_u64;
    let ret = unsafe {
        GetDiskFreeSpaceExW(
            buf.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            mem::transmute(&mut free_space),
        )
    };
    if ret == 0 {
        let (_, msg) = last_win32_error();
        let trimmed_msg = msg.trim_end();
        return Err(io::Error::new(io::ErrorKind::Other, trimmed_msg));
    }

    Ok(free_space)
}

#[cfg(not(windows))]
pub fn disk_free_space(path: impl AsRef<Path>) -> Result<u64, io::Error> {
    use std::mem::MaybeUninit;

    let mut st: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
    let p = CString::new(
        path.as_ref()
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid filename"))?,
    )?;

    let ret = unsafe { libc::statvfs(p.as_ptr(), st.as_mut_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let st = unsafe { st.assume_init() };
    if cfg!(target_os = "macos") {
        Ok(st.f_frsize as u64 * st.f_bfree as u64)
    } else if cfg!(target_os = "linux") {
        Ok(st.f_bsize as u64 * st.f_bfree as u64)
    } else {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::disk_free_space;

    #[test]
    fn test_disk_free_space() {
        let df = disk_free_space("/Users").unwrap();
        dbg!(&df);
    }
}
