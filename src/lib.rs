#![crate_name="otp"]
#![crate_type="lib"]

extern crate openssl;
extern crate serialize;
extern crate base32;
extern crate time;

use time::get_time;
use openssl::crypto::hash::SHA1;
use openssl::crypto::hmac::HMAC;

use std::io::extensions::{u64_to_be_bytes, u64_from_be_bytes};

/// Decodes a secret (given as an RFC4648 base32-encoded ASCII string)
/// into a byte string
fn decode_secret(secret: &[Ascii]) -> Option<Vec<u8>> {
    base32::decode(base32::UnpaddedRFC4648Base32, secret)
}

/// Calculates the HMAC digest for the given secret and counter.
fn calc_digest(decoded_secret: &[u8], counter: u64) -> Vec<u8> {
    let mut hmac = HMAC(SHA1, decoded_secret);
    u64_to_be_bytes(counter, 8, |bytes| {
        hmac.update(bytes);
    });

    let rv = hmac.final();
    println!("digest {}", rv);
    rv
}

/// Encodes the HMAC digest into a 6-digit integer.
fn encode_digest(digest: &[u8]) -> u32 {
    let offset = *digest.last().unwrap() as uint & 0xf;
    let code = u64_from_be_bytes(digest, offset, 4) as u32;

    (code & 0x7fffffff) % 1_000_000
}

/// Performs the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
/// (HOTP) given an RFC4648 base32 encoded secret, and an integer counter.
pub fn make_hotp(secret: &[Ascii], counter: u64) -> Option<u32> {
    decode_secret(secret).map(|decoded| {
        encode_digest(calc_digest(decoded.as_slice(), counter).as_slice())
    })
}

/// Helper function for `make_totp` to make it testable. Note that times
/// before Unix epoch are not supported.
fn make_totp_helper(secret: &[Ascii], time_step: u64, skew: i64, time: u64) -> Option<u32> {
    let counter = ((time as i64 + skew) as u64) / time_step;
    make_hotp(secret, counter)
}

/// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
/// (TOTP) given an RFC4648 base32 encoded secret, the time step in seconds,
/// and a skew in seconds.
pub fn make_totp(secret: &[Ascii], time_step: u64, skew: i64) -> Option<u32> {
    let now = get_time();
    make_totp_helper(secret, time_step, skew, now.sec as u64)
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
