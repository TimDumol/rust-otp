#![crate_name="otp"]
#![crate_type="lib"]

extern crate openssl;
extern crate serialize;
extern crate base32;
extern crate time;

use time::get_time;
use openssl::crypto::hash::SHA1;
use openssl::crypto::hmac::HMAC;

/// Decodes a secret (given as an RFC4648 base32-encoded ASCII string)
/// into a byte string
fn decode_secret(secret: &[Ascii]) -> Option<Vec<u8>> {
    base32::decode(base32::UnpaddedRFC4648Base32, secret)
}

/// Calculates the HMAC digest for the given secret and counter.
fn calc_digest(decoded_secret: &[u8], counter: i64) -> Vec<u8> {
    let bytestr = [((counter >> 56) & 0xff) as u8,
            ((counter >> 48) & 0xff) as u8,
            ((counter >> 40) & 0xff) as u8,
            ((counter >> 32) & 0xff) as u8,
            ((counter >> 24) & 0xff) as u8,
            ((counter >> 16) & 0xff) as u8,
            ((counter >> 8)  & 0xff) as u8,
            ( counter        & 0xff) as u8];
    let mut hmac = HMAC(SHA1, decoded_secret);
    hmac.update(bytestr);
    let rv = hmac.final();
    println!("digest {}", rv);
    rv
}

/// Encodes the HMAC digest into a 6-digit integer.
fn encode_digest(digest: &[u8]) -> u32 {
    let index = (digest[digest.len()-1] & 0xf) as uint;
    let word: u32 = (((digest[index] as u32) & 0x7f) << 24) |
        (((digest[index + 1] as u32) & 0xff) << 16) |
        (((digest[index + 2] as u32) & 0xff) << 8) |
        (( digest[index + 3] as u32) & 0xff);
    word % 1000000
}

/// Performs the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm) 
/// (HOTP) given an RFC4648 base32 encoded secret, and an integer counter.
pub fn make_hotp(secret: &[Ascii], counter: i64) -> Option<u32> {
    let decoded_option = decode_secret(secret);
    match decoded_option {
        None => None,
        Some(decoded) => {
            Some(encode_digest(calc_digest(decoded.as_slice(), counter).as_slice()))
        }
    }
}

/// Helper function for `make_totp` to make it testable.
fn make_totp_helper(secret: &[Ascii], time_step: i64, skew: i64, time: i64) -> Option<u32> {
    let decoded_option = decode_secret(secret);
    match decoded_option {
        None => None,
        Some(decoded) => {
            Some(encode_digest(calc_digest(decoded.as_slice(), (time + skew)/time_step).as_slice()))
        }
    }
}

/// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) 
/// (TOTP) given an RFC4648 base32 encoded secret, the time step in seconds,
/// and a skew in seconds.
pub fn make_totp(secret: &[Ascii], time_step: i64, skew: i64) -> Option<u32> {
    let now = get_time();
    make_totp_helper(secret, time_step, skew, now.sec)
}

#[cfg(test)]
mod tests {
    use super::{make_hotp, make_totp_helper};

    #[test]
    fn hotp() {
        assert_eq!(make_hotp("base32secret3232".to_ascii(), 0), Some(260182));
        assert_eq!(make_hotp("base32secret3232".to_ascii(), 1), Some(55283));
        assert_eq!(make_hotp("base32secret3232".to_ascii(), 1401), Some(316439));
    }

    #[test]
    fn totp() {
        assert_eq!(make_totp_helper("base32secret3232".to_ascii(), 30, 0, 0), Some(260182));
        assert_eq!(make_totp_helper("base32secret3232".to_ascii(), 3600, 0, 7), Some(260182));
        assert_eq!(make_totp_helper("base32secret3232".to_ascii(), 30, 0, 35), Some(55283));
        assert_eq!(make_totp_helper("base32secret3232".to_ascii(), 1, -2, 1403), Some(316439));
    }
}
