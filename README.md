# rust-otp

[![Build Status](https://travis-ci.org/TimDumol/rust-otp.svg?branch=master)](https://travis-ci.org/TimDumol/rust-otp)

`rust-otp` is a Rust library for performing the [HMAC-based One-time Passsword Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm) as per [RFC 4226](http://tools.ietf.org/html/rfc4226) and the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm) as per [RFC 6238](http://tools.ietf.org/html/rfc6238). These are also the algorithms many mobile-based 2FA apps, such as [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2) and [Authy](https://www.authy.com/), use to generate 2FA codes.

# Installation

Just add the library as a dependency by adding the following section to your
`Cargo.toml` file.

```toml
[dependencies.otp]

git = "https://github.com/TimDumol/rust-otp"
```

# Usage

```rust
// first argument is the secret, second argument is the counter
assert_eq!(make_hotp("base32secret3232".to_ascii(), 0), Some(260182));

// first argument is the secret, followed by the time step in seconds (Google
// Authenticator uses a time step of 30), and then the skew in seconds
// (often used when calculating HOTPs for a sequence of consecutive
// time intervals, to deal with potential latency and desynchronization).
assert_eq!(make_totp("base32secret3232".to_ascii(), 30, 0), Some(260182)); // true on Unix epoch
```


# License

`rust-otp` is licensed under the [MIT license](http://opensource.org/licenses/MIT).
The full license is included in this repository in `LICENSE.md`.
