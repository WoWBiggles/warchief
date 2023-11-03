use config::{Config, File, FileFormat};

pub const DB_URL: &str = "db.url";

pub const RECAPTCHA_SECRET: &str = "recaptcha.secret";

pub const GEOIP_ENABLED: &str = "geoip.enabled";
pub const GEOIP_WHITELISTED_COUNTRIES: &str = "geoip.whitelist.countries";
pub const GEOIP_WHITELISTED_CONTINENTS: &str = "geoip.whitelist.continents";
pub const GEOIP_BLACKLISTED_COUNTRIES: &str = "geoip.blacklist.countries";
pub const GEOIP_BLACKLISTED_CONTINENTS: &str = "geoip.blacklist.continents";

pub fn init_config() -> Config {
    Config::builder()
        .add_source(File::new("config.toml", FileFormat::Toml))
        .build()
        .expect("Config to build correctly.")
}
