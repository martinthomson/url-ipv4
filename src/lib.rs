#![deny(warnings, clippy::pedantic)]

use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct NotAnIp;
impl fmt::Display for NotAnIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not an IPv4 address")
    }
}
impl std::error::Error for NotAnIp {}
type Res<T> = Result<T, NotAnIp>;

struct IpParser<'a> {
    /// Buffer
    s: &'a [u8],
    /// Cursor
    i: usize,
}

impl<'a> IpParser<'a> {
    const ZERO: u8 = 0x30;
    const DOT: u8 = 0x2e;
    const SMALL_X: u8 = 0x78;
    const BIG_X: u8 = 0x58;

    fn new(s: &'a [u8]) -> Self {
        Self { s, i: 0 }
    }

    fn c(&self) -> u8 {
        self.s[self.i]
    }

    fn next(&mut self) {
        debug_assert!(!self.end());
        self.i += 1;
    }

    fn end(&self) -> bool {
        self.s.len() == self.i
    }

    fn radix(&mut self) -> Res<u32> {
        if self.end() || self.c() == Self::DOT {
            Err(NotAnIp)
        } else if self.c() == Self::ZERO {
            self.next();
            if !self.end() && (self.c() == Self::SMALL_X || self.c() == Self::BIG_X) {
                self.next();
                if self.end() {
                    Err(NotAnIp)
                } else {
                    Ok(16)
                }
            } else {
                Ok(8)
            }
        } else {
            Ok(10)
        }
    }

    #[allow(clippy::cast_possible_truncation)] // Using explicit checks.
    fn value(&mut self) -> Res<u32> {
        let radix = self.radix()?;
        if self.end() {
            return Ok(0);
        }
        let mut v = 0_u64;
        while let Some(x) = char::from(self.c()).to_digit(radix) {
            v = v * u64::from(radix) + u64::from(x);
            if v > 0xffff_ffff {
                return Err(NotAnIp);
            }
            self.next();
            if self.end() {
                return Ok(v as u32);
            }
        }
        if self.c() == Self::DOT {
            Ok(v as u32)
        } else {
            Err(NotAnIp)
        }
    }

    fn last_part(v: u32, part: u32, end: bool) -> Res<u32> {
        if end {
            if v.leading_zeros() < part * 8 {
                Err(NotAnIp)
            } else {
                Ok(v)
            }
        } else {
            Err(NotAnIp)
        }
    }

    pub fn parse<'b>(ip: impl AsRef<[u8]> + 'b) -> Res<u32> {
        let mut checker = IpParser::new(ip.as_ref());
        let mut v = 0_u32;
        for part in 0..3 {
            let x = checker.value()?;
            if x >= 256 || checker.end() {
                return Ok(v | Self::last_part(x, part, checker.end())?);
            }

            debug_assert_eq!(checker.c(), Self::DOT);
            checker.next();
            v |= x << (24 - (part * 8));
        }
        let x = checker.value()?;
        Ok(v | Self::last_part(x, 3, checker.end())?)
    }
}

/// Determine if the given string contains an IPv4 address.
/// This doesn't use `std::net::Ipv4Addr::from_str` because
/// that parser doesn't do all the weird stuff in the URL spec[1].
///
/// [1] <https://url.spec.whatwg.org/#concept-ipv4-parser>
pub fn is_ipv4(ip: impl AsRef<[u8]>) -> bool {
    IpParser::parse(ip).is_ok()
}

/// Parse an IP address using the completely bonkers algorithm from
/// the URL spec[1].
///
/// # Errors
/// When the address is not well formed.
///
/// [1] <https://url.spec.whatwg.org/#concept-ipv4-parser>
pub fn parse(ip: impl AsRef<[u8]>) -> Res<Ipv4Addr> {
    IpParser::parse(ip).map(Ipv4Addr::from)
}

#[cfg(test)]
mod test {
    use super::{is_ipv4, parse};
    use std::net::Ipv4Addr;

    fn valid(ip: &str, a: u8, b: u8, c: u8, d: u8) {
        assert_eq!(parse(ip).unwrap(), Ipv4Addr::new(a, b, c, d));
    }

    #[test]
    fn decimal() {
        valid("0.0.0.0", 0, 0, 0, 0);
        valid("1.1.1.1", 1, 1, 1, 1);
        valid("255.255.255.255", 255, 255, 255, 255);
        valid("255.255.65535", 255, 255, 255, 255);
        valid("255.16777215", 255, 255, 255, 255);
        valid("4294967295", 255, 255, 255, 255);
    }

    #[test]
    fn octal() {
        valid("0377.0377.0377.0377", 255, 255, 255, 255);
        valid("0377.0377.0177777", 255, 255, 255, 255);
        valid("0377.077777777", 255, 255, 255, 255);
        valid("037777777777", 255, 255, 255, 255);
        valid("00377.00377.00377.00377", 255, 255, 255, 255);
        valid("00377.00377.00177777", 255, 255, 255, 255);
        valid("00377.0077777777", 255, 255, 255, 255);
        valid("0037777777777", 255, 255, 255, 255);
    }

    #[test]
    fn hex() {
        valid("0xff.0xff.0xff.0xff", 255, 255, 255, 255);
        valid("0xff.0xff.0xffff", 255, 255, 255, 255);
        valid("0xff.0xffffff", 255, 255, 255, 255);
        valid("0xffffffff", 255, 255, 255, 255);
        valid("0XFF.0XFF.0XFF.0XFF", 255, 255, 255, 255);
        valid("0XFF.0XFF.0XFFFF", 255, 255, 255, 255);
        valid("0XFF.0XFFFFFF", 255, 255, 255, 255);
        valid("0XFFFFFFFF", 255, 255, 255, 255);
        valid("0x0ff.0x0ff.0x0ff.0x0ff", 255, 255, 255, 255);
        valid("0x0ff.0x0ff.0x0ffff", 255, 255, 255, 255);
        valid("0x0ff.0x0ffffff", 255, 255, 255, 255);
        valid("0x0ffffffff", 255, 255, 255, 255);
    }

    #[test]
    fn many_zeroes() {
        valid("00000000000000000000000000000000000000000", 0, 0, 0, 0);
        valid("00000000000000000000000000000000000000001", 0, 0, 0, 1);
    }

    #[test]
    fn every_decimal() {
        for i in 0..10 {
            valid(&format!("{}", i), 0, 0, 0, i);
        }
    }

    #[test]
    fn every_octal() {
        for i in 0..8 {
            valid(&format!("0{}", i), 0, 0, 0, i);
        }
    }

    #[test]
    fn every_hex() {
        for i in 0..16 {
            valid(&format!("0x{:x}", i), 0, 0, 0, i);
            valid(&format!("0x{:X}", i), 0, 0, 0, i);
        }
    }

    #[test]
    fn loopback() {
        valid("127.0.0.1", 127, 0, 0, 1);
        valid("127.0.1", 127, 0, 0, 1);
        valid("127.1", 127, 0, 0, 1);
        valid("2130706433", 127, 0, 0, 1);
        valid("017700000001", 127, 0, 0, 1);
    }

    fn invalid(ip: &str) {
        assert!(!is_ipv4(ip));
    }

    #[test]
    fn too_many_dots() {
        invalid("127..1");
        invalid("0.0.0.0.0");
        invalid("1.2.3.4.5");
        invalid("1..2.3");
        invalid("1.2.3.");
        invalid(".1.2.3");
    }
    #[test]
    fn large_values() {
        invalid("999999999999999999999999999999999");
        invalid("07777777777777777777777777777777777777777");
        invalid("256.255.255.255");
        invalid("255.256.255.255");
        invalid("255.255.256.255");
        invalid("255.255.255.256");
        invalid("255.255.65536");
        invalid("255.16777216");
        invalid("4294967296");
        invalid("0400.0377.0377.0377");
        invalid("0377.0400.0377.0377");
        invalid("0377.0377.0400.0377");
        invalid("0377.0377.0377.0400");
        invalid("0377.0377.0200000");
        invalid("0377.0100000000");
        invalid("040000000000");
        invalid("0x100.0xff.0xff.0xff");
        invalid("0xff.0x100.0xff.0xff");
        invalid("0xff.0xff.0x100.0xff");
        invalid("0xff.0xff.0xff.0x100");
        invalid("0xff.0xff.0x10000");
        invalid("0xff.0x1000000");
        invalid("0x100000000");
    }

    #[test]
    fn non_digit() {
        invalid("");
        invalid("08");
        invalid("09");
        invalid("a");
        invalid("0xg");
        invalid("0XG");
        invalid("\u{2077}");
    }

    #[test]
    fn truncate_hex() {
        invalid("0x");
    }
}
