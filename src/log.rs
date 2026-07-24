//! Logging support

use log::{Level, LevelFilter, Metadata, Record, SetLoggerError};

pub struct ConsoleLogger {
    max_level: Option<Level>,
}

impl ConsoleLogger {
    pub fn init(max_level: LevelFilter) -> Result<(), SetLoggerError> {
        log::set_boxed_logger(Box::new(ConsoleLogger {
            max_level: max_level.to_level(),
        }))
        .map(|()| log::set_max_level(max_level))
    }
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.max_level
            .map(|max| metadata.level() <= max)
            .unwrap_or(false)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let prefix = match record.metadata().level() {
                Level::Trace => "***",
                Level::Debug => "*",
                _ => "",
            };
            println!("{}{}", prefix, record.args());
        }
    }

    fn flush(&self) {}
}
