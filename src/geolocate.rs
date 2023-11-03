#[allow(unused_imports)]
use std::str::FromStr;
use std::{io, net::IpAddr};

use geoip2::{Country, Error, Reader};

use crate::structs::IpLocation;

pub fn load_mmdb_data() -> Result<Vec<u8>, io::Error> {
    std::fs::read("static/GeoLite2-Country.mmdb")
}

pub fn geolocate_ip_country(mmdb_buffer: &Vec<u8>, ip: IpAddr) -> Result<IpLocation, Error> {
    let reader = Reader::<Country>::from_bytes(mmdb_buffer)?;
    let result = reader.lookup(ip)?;

    Ok(IpLocation::new(result.country, result.continent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locate_random_valid_ips() {
        let mmdb_buffer = load_mmdb_data().unwrap();

        let british_ip = IpAddr::from_str("81.2.69.142").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, british_ip).unwrap(),
            IpLocation {
                country_code: Some(String::from("GB")),
                continent_code: Some(String::from("EU")),
            }
        );

        let german_ip = IpAddr::from_str("88.198.248.254").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, german_ip).unwrap(),
            IpLocation {
                country_code: Some(String::from("DE")),
                continent_code: Some(String::from("EU")),
            }
        );

        let finnish_ip = IpAddr::from_str("95.217.255.81").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, finnish_ip).unwrap(),
            IpLocation {
                country_code: Some(String::from("FI")),
                continent_code: Some(String::from("EU")),
            }
        );

        let singapore_ip = IpAddr::from_str("138.199.60.31").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, singapore_ip).unwrap(),
            IpLocation {
                country_code: Some(String::from("SG")),
                continent_code: Some(String::from("AS")),
            }
        );
    }

    #[test]
    fn locating_ips_close_to_borders() {
        let mmdb_buffer = load_mmdb_data().unwrap();

        let chinese_ip = IpAddr::from_str("221.192.199.49").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, chinese_ip)
                .unwrap()
                .country_code,
            Some(String::from("CN"))
        );

        let mongolian_ip = IpAddr::from_str("43.231.112.70").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, mongolian_ip)
                .unwrap()
                .country_code,
            Some(String::from("MN"))
        );

        let vladivostock_ip = IpAddr::from_str("5.101.218.107").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, vladivostock_ip)
                .unwrap()
                .country_code,
            Some(String::from("RU"))
        );

        let iran_ip = IpAddr::from_str("95.38.60.151").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, iran_ip)
                .unwrap()
                .country_code,
            Some(String::from("IR"))
        );

        let saudi_ip = IpAddr::from_str("192.29.224.220").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, saudi_ip)
                .unwrap()
                .country_code,
            Some(String::from("SA"))
        );
    }

    #[test]
    fn locating_invalid_ip_fails() {
        let mmdb_buffer = load_mmdb_data().unwrap();

        let random_ip = IpAddr::from_str("245.115.43.106").unwrap();
        assert_eq!(
            geolocate_ip_country(&mmdb_buffer, random_ip),
            Err(Error::NotFound)
        );
    }
}
