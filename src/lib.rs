pub mod ffi;
pub use log::LevelFilter;
use anyhow::bail;
use libc::localtime_r;
use log::info;
use std::{io::Write, ffi::{c_char, CString, CStr}, mem, ptr, path::Path, borrow::Cow};

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
                let ts = format_date(unsafe {
                    libc::time(ptr::null_mut()) as u64
                }, &self.date_format);
                let ts =
                    match ts {
                        Ok(ts) => ts,
                        Err(_) => "".to_string()
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
    let _ = Logger::builder()
        .build();
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

