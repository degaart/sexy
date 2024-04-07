#![allow(deprecated)]

pub mod ffi;

pub use log::LevelFilter;

use anyhow::bail;
use log::info;
use rand::Rng;
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

const EPOCH_YEAR: u32 = 1970;
const DAYS_IN_MONTH: [u32;13] = [ 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 ];
const MONTH_DAY_OFFSETS: [u32;13] = [ 0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 ];
const DAYS_PER_YEAR: u64 = 365;
const SECONDS_PER_DAY: u64 = 86400;
const SECONDS_PER_HOUR: u64 = 3600;
const SECONDS_PER_MINUTE: u64 = 60;

#[derive(Debug, Clone)]
pub struct DateToUnixError {
    msg: String,
    val: u32,
}

impl DateToUnixError {
    fn new(msg: &str, val: u32) -> Self {
        Self { msg: msg.to_string(), val }
    }
}

impl std::fmt::Display for DateToUnixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.msg, self.val)
    }
}

pub fn date_to_unix(year: u32, mon: u32, day: u32, hour: u32, min: u32, sec: u32) -> Result<u64, DateToUnixError> {
    if year < EPOCH_YEAR {
        return Err(DateToUnixError::new("Invalid year", year));
    } else if mon < 1 || mon > 12 {
        return Err(DateToUnixError::new("Invalid month", mon));
    } else if day < 1 {
        return Err(DateToUnixError::new("Invalid day", day));
    } else if hour > 23 {
        return Err(DateToUnixError::new("Invalid hour", hour));
    } else if min > 59 {
        return Err(DateToUnixError::new("Invalid minute", min));
    } else if sec > 59 {
        return Err(DateToUnixError::new("Invalid second", sec));
    }

    let mut is_leap = (year % 4) == 0;
    if year % 100 == 0 {
        is_leap = false;
    }
    if year % 400 == 0 {
        is_leap = true;
    }

    let mut days_in_month = DAYS_IN_MONTH[mon as usize];
    if mon == 2 && is_leap {
        days_in_month += 1;
    }

    if day > days_in_month {
        return Err(DateToUnixError::new("Invalid day", day));
    }

    /* years */
    let mut result = (year - EPOCH_YEAR) as u64 * DAYS_PER_YEAR * SECONDS_PER_DAY;

    /* leap years, by 4 */
    result += ((year - 1969) / 4) as u64 * SECONDS_PER_DAY;

    /* leap years, by 100 */
    result -= ((year - 1901) / 100) as u64 * SECONDS_PER_DAY;

    /* leap years, by 400 */
    result += ((year - 1601) / 400) as u64 * SECONDS_PER_DAY;

    /* months */
    result += MONTH_DAY_OFFSETS[mon as usize] as u64 * SECONDS_PER_DAY;
    if mon > 2 && is_leap {
        result += SECONDS_PER_DAY;
    }

    /* days */
    result += (day - 1) as u64 * SECONDS_PER_DAY;

    /* hour */
    result += hour as u64 * SECONDS_PER_HOUR;

    /* minute */
    result += min as u64 * SECONDS_PER_MINUTE;

    /* seconds */
    result += sec as u64;

    Ok(result)
}

pub const LOWER: u32 = 1;
pub const UPPER: u32 = 2;
pub const ALPHA: u32 = LOWER | UPPER;
pub const NUMERIC: u32 = 4;
pub const ALPHANUMERIC: u32 = ALPHA | NUMERIC;
pub const SPACE: u32 = 8;
pub const DASH: u32 = 16;
pub const UNDERSCORE: u32 = 32;

pub fn gen_random_string(length: usize, charset: u32) -> String {
    let mut chars = Vec::new();
    if (charset & LOWER) != 0 {
        for i in 'a'..'z' {
            chars.push(i);
        }
    }
    if (charset & UPPER) != 0 {
        for i in 'A'..'Z' {
            chars.push(i);
        }
    }
    if (charset & NUMERIC) != 0 {
        for i in '0'..'9' {
            chars.push(i);
        }
    }
    if (charset & SPACE) != 0 {
        chars.push(' ');
    }
    if (charset & DASH) != 0 {
        chars.push('-');
    }
    if(charset & UNDERSCORE) != 0 {
        chars.push('_');
    }
    assert_ne!(chars.len(), 0);

    let mut rng = rand::thread_rng();
    let mut result = Vec::new();
    for _ in 0..length {
        result.push(chars[rng.gen_range(0..chars.len())]);
    }

    String::from_iter(&result)
}

pub const BASE64_NO_PAD: u32 = 0;
pub const BASE64_PAD: u32 = 1;

pub fn base64_encode(data: &[u8], flags: u32) -> String {
    use base64::engine::Engine;
    if (flags & BASE64_PAD) != 0 {
        base64::engine::general_purpose::STANDARD.encode(data)
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
    }
}

pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::engine::Engine;
    base64::engine::general_purpose::STANDARD.decode(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{disk_free_space, date_to_unix};

    #[test]
    fn test_disk_free_space() {
        let df = disk_free_space("/Users").unwrap();
        dbg!(&df);
    }

    #[test]
    fn test_date_to_unix() {
        assert_eq!(0,          date_to_unix(1970, 1, 1, 0, 0, 0).unwrap());
        assert_eq!(504921600,  date_to_unix(1986, 1, 1, 0, 0, 0).unwrap());
        assert_eq!(536457599,  date_to_unix(1986, 12, 31, 23, 59, 59).unwrap());
        assert_eq!(1234567890, date_to_unix(2009, 2, 13, 23, 31, 30).unwrap());
        assert_eq!(2147483647, date_to_unix(2038, 1, 19, 3, 14, 7).unwrap());
        assert_eq!(2147483648, date_to_unix(2038, 1, 19, 3, 14, 8).unwrap());
        assert_eq!(4294967295, date_to_unix(2106, 2, 7, 6, 28, 15).unwrap());
        assert_eq!(4294967296, date_to_unix(2106, 2, 7, 6, 28, 16).unwrap());
    }

    #[test]
    fn test_random_string() {
        let charset = ALPHANUMERIC | SPACE | DASH | UNDERSCORE;
        let length = 128;
        let result = gen_random_string(length, charset);
        println!("{result}");
    }

}

