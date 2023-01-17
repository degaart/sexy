use libc::localtime_r;
use log::info;
use std::{io::Write, ffi::{c_char, CString, CStr}, mem, ptr, path::Path, borrow::Cow};
pub mod ffi;
use anyhow::bail;

#[cfg(feature = "crypto")]
pub mod crypto;

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

pub fn init_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format(|buf, record| {
            let ts = format_date(unsafe { libc::time(ptr::null_mut()) as u64}, "%Y-%m-%d %H:%M:%S");
            let ts =
                match ts {
                    Ok(ts) => ts,
                    Err(_) => "".to_string()
                };
            if cfg!(debug_assertions) {
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
                    record.args())
            } else {
                writeln!(
                    buf,
                    "[{}][{}] {}",
                    ts,
                    record.level(),
                    record.args())
            }
        })
        .init();
}

pub struct LogExit {}

impl Drop for LogExit {
    fn drop(&mut self) {
        info!("Exited");
    }
}

extern "C" {
    fn strptime(buf: *const c_char, format: *const c_char, timeptr: *mut libc::tm) -> *const c_char;
    fn strftime(buf: *mut c_char, maxsize: usize, format: *const c_char, timeptr: *mut libc::tm) -> usize;
}

pub fn parse_date(s: &str, fmt: &str) -> anyhow::Result<u64> {
    let mut tm: libc::tm = unsafe { mem::zeroed() };
    let cs = CString::new(s)?;
    let cf = CString::new(fmt)?;
    let ret = unsafe { strptime(cs.as_ptr(), cf.as_ptr(), &mut tm) };
    if ret.is_null() {
        bail!("Invalid date string: {}", s);
    }
    let result = unsafe { libc::mktime(&mut tm) as u64 };
    Ok(result)
}

pub fn format_date(timestamp: u64, fmt: &str) -> anyhow::Result<String> {
    unsafe {
        let mut tm: libc::tm = mem::zeroed();
        localtime_r(mem::transmute(&timestamp), &mut tm);
        
        let mut buffer = [08; 4096];
        let cfmt = CString::new(fmt)?;
        let ret = strftime(buffer.as_mut_ptr() as *mut c_char, buffer.len(), cfmt.as_ptr(), &mut tm);
        if ret == 0 && fmt.len() > 0 {
            bail!("Failed to format time");
        }
        let result = CStr::from_ptr(buffer.as_ptr() as *const c_char).to_str()?;
        Ok(result.to_string())
    }
}

