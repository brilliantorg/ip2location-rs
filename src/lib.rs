extern crate byteorder;
extern crate failure;
extern crate memmap;
extern crate num_traits;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use std::default::Default;
use std::fs::File;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use byteorder::{LittleEndian, ReadBytesExt};
use failure::{Error, err_msg};
use memmap::Mmap;
use num_traits::PrimInt;

mod positions;

#[derive(Debug)]
pub struct IP2Location {
    db_path: String,
    db_buffer: Mmap,
    db_type: usize,
    db_column: usize,
    db_year: usize,
    db_month: usize,
    db_day: usize,
    ipv4_db_count: usize,
    ipv4_db_addr: usize,
    ipv6_db_count: usize,
    ipv6_db_addr: usize,
    ipv4_index_base_addr: usize,
    ipv6_index_base_addr: usize,
}

impl IP2Location {
    pub fn open(db_path: &str) -> Result<IP2Location, Error> {
        let file = File::open(db_path)?;
        let db_buffer = unsafe { Mmap::map(&file)? };

        let mut cursor = Cursor::new(db_buffer);
        let db_type = cursor.read_u8()? as usize;
        let db_column = cursor.read_u8()? as usize;
        let db_year = cursor.read_u8()? as usize;
        let db_month = cursor.read_u8()? as usize;
        let db_day = cursor.read_u8()? as usize;
        let ipv4_db_count = cursor.read_u32::<LittleEndian>()? as usize;
        let ipv4_db_addr = cursor.read_u32::<LittleEndian>()? as usize;
        let ipv6_db_count = cursor.read_u32::<LittleEndian>()? as usize;
        let ipv6_db_addr = cursor.read_u32::<LittleEndian>()? as usize;
        let ipv4_index_base_addr = cursor.read_u32::<LittleEndian>()? as usize;
        let ipv6_index_base_addr = cursor.read_u32::<LittleEndian>()? as usize;

        let db_buffer = cursor.into_inner();

        Ok(IP2Location{
            db_path: db_path.to_string(),
            db_buffer: db_buffer,
            db_type: db_type,
            db_column: db_column,
            db_year: db_year,
            db_month: db_month,
            db_day: db_day,
            ipv4_db_count: ipv4_db_count,
            ipv4_db_addr: ipv4_db_addr,
            ipv6_db_count: ipv6_db_count,
            ipv6_db_addr: ipv6_db_addr,
            ipv4_index_base_addr: ipv4_index_base_addr,
            ipv6_index_base_addr: ipv6_index_base_addr,
        })
    }

    fn read_u32(&self, offset: usize) -> Result<u32, Error> {
        let mut four_bytes = &self.db_buffer[offset - 1..offset + 3];
        Ok(four_bytes.read_u32::<LittleEndian>()?)
    }

    fn read_string(&self, offset: usize) -> Result<String, Error> {
        let string_len = self.db_buffer[offset - 1] as usize;
        let string_bytes = &self.db_buffer[offset..(offset + string_len)];
        Ok(String::from_utf8(string_bytes.to_vec())?)
    }

    fn read_f32(&self, offset: usize) -> Result<f32, Error> {
        let mut four_bytes = &self.db_buffer[offset - 1..offset + 3];
        Ok(four_bytes.read_f32::<LittleEndian>()?)
    }

    fn read_ipv4(&self, offset: usize) -> Result<u32, Error> {
        self.read_u32(offset)
    }

    fn read_ipv6(&self, offset: usize) -> Result<u128, Error> {
        let a = self.read_u32(offset)? as u128;
        let b = self.read_u32(offset + 4)? as u128;
        let c = self.read_u32(offset + 8)? as u128;
        let d = self.read_u32(offset + 12)? as u128;
        Ok((d << 96) | (c << 64) | (b << 32) | a)
    }

    fn read_record(&self, ipaddr: IpAddr, base_db_addr: usize, offset: usize, index: usize) -> Result<Option<IP2LocationRecord>, Error> {
        let mut rec = IP2LocationRecord{..Default::default()};

        match ipaddr {
            IpAddr::V4(_) => {
                rec.ip = Some(
                    Ipv4Addr::from(
                        self.read_ipv4(self.ipv4_db_addr + (index) * self.db_column * 4)?
                    ).to_string()
                );
            }
            IpAddr::V6(_) => {
                rec.ip = Some(
                    Ipv6Addr::from(
                        self.read_ipv6(self.ipv6_db_addr + (index) * self.db_column * 4)?
                    ).to_string()
                );
            }
        }

        let calc_off = |what: [usize; 25], index: usize| {
            base_db_addr + index * (self.db_column * 4 + offset) + offset + 4 * (what[self.db_type] - 1)
        };

        if positions::COUNTRY[self.db_type] != 0 {
            rec.country_short = Some(self.read_string(self.read_u32(calc_off(positions::COUNTRY, index))? as usize + 1)?);
            rec.country_long = Some(self.read_string(self.read_u32(calc_off(positions::COUNTRY, index))? as usize + 4)?);
        }

        if positions::REGION[self.db_type] != 0 {
            rec.region = Some(self.read_string(self.read_u32(calc_off(positions::REGION, index))? as usize + 1)?);
        }

        if positions::CITY[self.db_type] != 0 {
            rec.city = Some(self.read_string(self.read_u32(calc_off(positions::CITY, index))? as usize + 1)?);
        }

        if positions::ISP[self.db_type] != 0 {
            rec.isp = Some(self.read_string(self.read_u32(calc_off(positions::ISP, index))? as usize + 1)?);
        }

        if positions::LATITUDE[self.db_type] != 0 {
            rec.latitude = Some(self.read_f32(calc_off(positions::LATITUDE, index))?);
        }

        if positions::LONGITUDE[self.db_type] != 0 {
            rec.longitude = Some(self.read_f32(calc_off(positions::LONGITUDE, index))?);
        }

        if positions::DOMAIN[self.db_type] != 0 {
            rec.domain = Some(self.read_string(self.read_u32(calc_off(positions::DOMAIN, index))? as usize + 1)?);
        }

        if positions::ZIPCODE[self.db_type] != 0 {
            rec.zipcode = Some(self.read_string(self.read_u32(calc_off(positions::ZIPCODE, index))? as usize + 1)?);
        }

        if positions::TIMEZONE[self.db_type] != 0 {
            rec.timezone = Some(self.read_string(self.read_u32(calc_off(positions::TIMEZONE, index))? as usize + 1)?);
        }

        if positions::NETSPEED[self.db_type] != 0 {
            rec.netspeed = Some(self.read_string(self.read_u32(calc_off(positions::NETSPEED, index))? as usize + 1)?);
        }

        if positions::IDDCODE[self.db_type] != 0 {
            rec.iddcode = Some(self.read_string(self.read_u32(calc_off(positions::IDDCODE, index))? as usize + 1)?);
        }

        if positions::AREACODE[self.db_type] != 0 {
            rec.area_code = Some(self.read_string(self.read_u32(calc_off(positions::AREACODE, index))? as usize + 1)?);
        }

        if positions::WEATHERSTATIONCODE[self.db_type] != 0 {
            rec.weather_code = Some(self.read_string(self.read_u32(calc_off(positions::WEATHERSTATIONCODE, index))? as usize + 1)?);
        }

        if positions::WEATHERSTATIONNAME[self.db_type] != 0 {
            rec.weather_name = Some(self.read_string(self.read_u32(calc_off(positions::WEATHERSTATIONNAME, index))? as usize + 1)?);
        }

        if positions::MCC[self.db_type] != 0 {
            rec.mcc = Some(self.read_string(self.read_u32(calc_off(positions::MCC, index))? as usize + 1)?);
        }

        if positions::MNC[self.db_type] != 0 {
            rec.mnc = Some(self.read_string(self.read_u32(calc_off(positions::MNC, index))? as usize + 1)?);
        }

        if positions::MOBILEBRAND[self.db_type] != 0 {
            rec.mobile_brand = Some(self.read_string(self.read_u32(calc_off(positions::MOBILEBRAND, index))? as usize + 1)?);
        }

        if positions::ELEVATION[self.db_type] != 0 {
            rec.elevation = Some(self.read_string(self.read_u32(calc_off(positions::ELEVATION, index))? as usize + 1)?);
        }

        if positions::USAGETYPE[self.db_type] != 0 {
            rec.usage_type = Some(self.read_string(self.read_u32(calc_off(positions::USAGETYPE, index))? as usize + 1)?);
        }

        Ok(Some(rec))
    }

    pub fn get_record(&self, ip_str: &str) -> Result<Option<IP2LocationRecord>, Error> {
        let offset;
        let mut low = 0;
        let mut high;
        let base_db_addr;

        let ipaddr = ip_str.parse::<IpAddr>()?;
        match ipaddr {
            IpAddr::V4(ipaddrv4) => {
                offset = 0;
                let ipno = u32::from(ipaddrv4);
                high = self.ipv4_db_count;
                base_db_addr = self.ipv4_db_addr;

                if self.ipv4_index_base_addr > 0 {
                    let indexpos = (((ipno >> 16) as usize) << 3) + self.ipv4_index_base_addr;
                    low = self.read_u32(indexpos)? as usize;
                    high = self.read_u32(indexpos + 4)? as usize;
                }
                let get_ip_range = |mid: usize| -> Result<(u32, u32), Error> {
                    let ipfrom = self.read_ipv4(base_db_addr + (mid) * (self.db_column * 4 + offset))?;
                    let ipto = self.read_ipv4(base_db_addr + (mid + 1) * (self.db_column * 4 + offset))?;
                    Ok((ipfrom, ipto))
                };
                self.binary_search(low, high, base_db_addr, offset, ipaddr, ipno, get_ip_range)
            }
            IpAddr::V6(ipaddrv6) => {
                if self.ipv6_db_count == 0 {
                    return Err(err_msg("Please use IPv6 BIN file for IPv6 Address."));
                }

                offset = 12;
                let ipno = u128::from(ipaddrv6);
                high = self.ipv6_db_count;
                base_db_addr = self.ipv6_db_addr;

                if self.ipv6_index_base_addr > 0 {
                    let indexpos = (((ipno >> 112) as usize) << 3) + self.ipv6_index_base_addr;
                    low = self.read_u32(indexpos)? as usize;
                    high = self.read_u32(indexpos + 4)? as usize;
                }
                let get_ip_range = |mid: usize| -> Result<(u128, u128), Error> {
                    let ipfrom = self.read_ipv6(base_db_addr + (mid) * (self.db_column * 4 + offset))?;
                    let ipto = self.read_ipv6(base_db_addr + (mid + 1) * (self.db_column * 4 + offset))?;
                    Ok((ipfrom, ipto))
                };
                self.binary_search(low, high, base_db_addr, offset, ipaddr, ipno, get_ip_range)
            }
        }
    }

    fn binary_search<T, F>(&self, low: usize, high: usize, base_db_addr: usize, offset: usize, ipaddr: IpAddr, ipno: T, get_ip_range: F) -> Result<Option<IP2LocationRecord>, Error>
        where T: PrimInt,
              F: Fn(usize) -> Result<(T, T), Error> {

        let mut low = low;
        let mut high = high;
        while low <= high {
            let mid = (low + high) / 2;
            let (ipfrom, ipto) = get_ip_range(mid)?;

            if ipfrom <= ipno && ipno < ipto {
                return Ok(self.read_record(ipaddr, base_db_addr, offset, mid)?);
            }
            else {
                if ipno < ipfrom {
                    high = mid - 1
                }
                else {
                    low = mid + 1
                }
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct IP2LocationRecord {
    pub ip: Option<String>,
    pub country_short: Option<String>,
    pub country_long: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub latitude: Option<f32>,
    pub longitude: Option<f32>,
    pub domain: Option<String>,
    pub zipcode: Option<String>,
    pub timezone: Option<String>,
    pub netspeed: Option<String>,
    pub iddcode: Option<String>,
    pub area_code: Option<String>,
    pub weather_code: Option<String>,
    pub weather_name: Option<String>,
    pub mcc: Option<String>,
    pub mnc: Option<String>,
    pub mobile_brand: Option<String>,
    pub elevation: Option<String>,
    pub usage_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_ipv4() {
        let test_cases = vec![
            ("19.5.10.1", "US"),
            ("25.5.10.2", "GB"),
            ("43.5.10.3", "JP"),
            ("47.5.10.4", "CA"),
            ("51.5.10.5", "GB"),
            ("53.5.10.6", "DE"),
            ("80.5.10.7", "GB"),
            ("81.5.10.8", "IL"),
            ("83.5.10.9", "PL"),
            ("85.5.10.0", "CH"),
        ];

        let mut test_data_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_data_path.push("test_data/IP-COUNTRY.BIN");

        let database = IP2Location::open(test_data_path.to_str().unwrap()).unwrap();
        for &(addr, country_short) in test_cases.iter() {
            let record = database.get_record(addr).unwrap().unwrap();
            assert_eq!(record.country_short.unwrap(), country_short);
        }
    }

    #[test]
    fn test_ipv6() {
        let test_cases = vec![
            ("2001:0200:0102::", "JP"),
            ("2a01:04f8:0d16:25c2::", "DE"),
            ("2a01:04f8:0d16:26c2::", "DE"),
            ("2a01:ad20::", "ES"),
            ("2a01:af60::", "PL"),
            ("2a01:b200::", "SK"),
            ("2a01:b340::", "IE"),
            ("2a01:b4c0::", "CZ"),
            ("2a01:b600:8001::", "IT"),
            ("2a01:b6c0::", "SE"),
        ];

        let mut test_data_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_data_path.push("test_data/IPV6-COUNTRY.BIN");

        let database = IP2Location::open(test_data_path.to_str().unwrap()).unwrap();
        for &(addr, country_short) in test_cases.iter() {
            let record = database.get_record(addr).unwrap().unwrap();
            assert_eq!(record.country_short.unwrap(), country_short);
        }
    }
}
