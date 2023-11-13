use config::{Config, ConfigError, File, FileFormat};

pub const SERVER_NAME: &str = "server_name";
pub const DOMAIN: &str = "domain";

pub const DB_URL: &str = "db.url";

pub const SMTP_HOST: &str = "smtp.host";
pub const SMTP_PORT: &str = "smtp.port";
pub const SMTP_USERNAME: &str = "smtp.username";
pub const SMTP_PASSWORD: &str = "smtp.password";

pub const EMAIL_VERIFICATION_ENABLED: &str = "email_verification.enabled";
pub const EMAIL_VERIFICATION_TOKEN_TIMEOUT_M: &str = "email_verification.token_timeout_m";

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
        .expect("config.toml must be in the working directory")
}

pub fn get_smtp_config(config: &Config) -> Result<(String, u16, String, String), ConfigError> {
    let smtp_host = config.get_string(SMTP_HOST)?;
    let smtp_port = config.get_int(SMTP_PORT)?;
    let smtp_username = config.get_string(SMTP_USERNAME)?;
    let smtp_password = config.get_string(SMTP_PASSWORD)?;

    Ok((
        smtp_host,
        smtp_port
            .try_into()
            .expect("SMTP port should be a valid port."),
        smtp_username,
        smtp_password,
    ))
}
