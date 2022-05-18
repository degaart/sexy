use std::io::Write;
use log::info;
pub mod ffi;

#[macro_export]
macro_rules! regex {
    ($re:literal $(,)?) => {{
        static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
        RE.get_or_init(|| regex::Regex::new($re).unwrap())
    }};
}

pub fn init_logging() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format(|buf, record| {
            let ts = chrono::Local::now().format("%y-%m-%d %H:%M:%S");
            writeln!(buf, "[{}][{}] {}", ts, record.level(), record.args())
        })
        .init();
}

pub struct LogExit {}

impl Drop for LogExit {
    fn drop(&mut self) {
        info!("Exited");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}