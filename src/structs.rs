use geoip2::models::{Continent, Country};
use serde::Serialize;

#[derive(PartialEq, Eq, Debug)]
pub struct IpLocation {
    pub country_code: Option<String>,
    pub continent_code: Option<String>,
}

impl IpLocation {
    pub fn new(country: Option<Country>, continent: Option<Continent>) -> Self {
        IpLocation {
            country_code: country
                .map(|c| c.iso_code.map(|code| code.to_string()))
                .flatten(),
            continent_code: continent
                .map(|c| c.code.map(|code| code.to_string()))
                .flatten(),
        }
    }
}
