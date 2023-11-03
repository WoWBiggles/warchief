use config::{Config, File, FileFormat};

pub const CONFIG_DB_URL: &str = "db.url";

pub const RECAPTCHA_SECRET: &str = "recaptcha.secret";

pub const CONFIG_GEOIP_ENABLED: &str = "geoip.enabled";

pub fn init_config() -> Config {
    Config::builder()
        .add_source(File::new("config.toml", FileFormat::Toml))
        .build()
        .expect("Config to build correctly.")
}
