/*!
Branca - Authenticated and Encrypted API tokens using modern cryptography.

This crate is a pure-Rust implementation of [Branca](https://branca.io)
which allows generating authenticated and encrypted tamper-proof tokens.
The [Branca specification](https://github.com/tuupola/branca-spec) is based on the
[Fernet specification](https://github.com/fernet/spec/blob/master/Spec.md) and is also similar in
its token format but it differs from the cipher that it uses for encryption and decryption and
the encoding format of the token. Branca uses [IETF XChaCha20-Poly1305 AEAD](https://tools.ietf.org/html/draft-arciszewski-xchacha-00#section-2.3.1)
for encryption and decryption and uses Base62 instead of Base64 for encoding the tokens to be URL safe.

A Branca token is encrypted then encoded into Base62, and looks like this:

`875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a`


The internal format of a Branca token looks like this:

`Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)`


The payload/ciphertext size can be of any arbitrary length, this means that contents of the payload can be anything from Text,
[JSON](https://en.wikipedia.org/wiki/JSON), [MessagePacks](http://msgpack.org/), [JWTs](https://jwt.io/), URLs, etc.
This allows a Branca Token to be a secure alternative to JWT, since it is authenticated and encrypted by default
and supports only one cipher as the standard; unlike JWT.

This [blog post](https://appelsiini.net/2017/branca-alternative-to-jwt/) explains
in more detail on using Branca tokens as an alternative to JWTs.

Also see: [branca-spec](https://github.com/tuupola/branca-spec) for more information about the token specification.

# Examples

A straightforward example of generating these tokens using the `Branca::new()` builder:

```rust
extern crate branca;
extern crate getrandom;

use branca::Branca;

fn main() {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).unwrap();

    let mut token = Branca::new(&key).unwrap();
    let ciphertext = token.encode(b"Hello World!").unwrap();

    let payload = token.decode(ciphertext.as_str(), 0).unwrap();
    println!("{}", String::from_utf8(payload).unwrap()); // "Hello World!"
}
```

You can also decide to set the other fields in the token before encoding it if you want to since
this is a builder method.


```rust
extern crate branca;
extern crate getrandom;

use branca::Branca;

fn main() {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).unwrap();

    let mut token = Branca::new(&key).unwrap();

    // You are able to use the builder to set the timestamp, ttL and the key.
    // However, the nonce cannot be set, as that is a security risk for
    // nonce-reuse misuse.

    // All properties inside of the token can be retrieved.

    let ciphertext = token
                      .set_timestamp(1234567890)
                      .set_key(key.to_vec())
                      .set_ttl(300);
                      //.encode(b"Hello World!").unwrap();

    let timestamp = token.timestamp(); // 1234567890
}
```

It is also possible to directly encode and decode functions without using the builder function.

Please note that Branca uses [Orion](https://github.com/orion-rs/orion) to generate secure random nonces
when using the encode() and builder methods. By default, Branca does not allow setting the nonce directly
since that there is a risk that it can be reused by the user which is a foot-gun.

```rust
extern crate branca;
extern crate getrandom;

use branca::{encode, decode};

let mut key = [0u8; 32];
getrandom::fill(&mut key).unwrap();

let token = encode(b"Hello World!", &key, 123206400).unwrap();
// token = "875G...p0a"

let ttl = 3600;
// The token will expire at timestamp + ttl
let payload = decode(token.as_str(), &key, 0).unwrap();

println!("{}", String::from_utf8(payload).unwrap());
// payload = "Hello World!"

```
*/

extern crate base_x;
extern crate byteorder;
extern crate orion;

#[cfg(test)]
extern crate serde;
#[cfg(test)]
#[macro_use]
extern crate serde_json;
#[cfg(test)]
#[macro_use]
extern crate serde_derive;

pub mod errors;

use self::errors::Error as BrancaError;
use base_x::{decode as b62_decode, encode as b62_encode};
use byteorder::*;
use orion::errors::UnknownCryptoError;
use orion::hazardous::aead::xchacha20poly1305::*;
use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
use orion::hazardous::stream::xchacha20::XCHACHA_NONCESIZE;
use orion::util::secure_rand_bytes;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

// Branca magic byte.
const VERSION: u8 = 0xBA;
// Base 62 alphabet.
const BASE62: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// The Branca struct defines the structure of a Branca token for encoding and decoding.
#[derive(Clone)]
pub struct Branca {
    /// The Branca Key which is exactly 32 bytes in length.
    key: Vec<u8>,
    /// The Branca Nonce which is exactly 24 bytes in length.
    /// A new nonce is generated each time `encode()` is called.
    nonce: Vec<u8>,
    /// The Time-to-live field (TTL) to set the number of seconds
    /// for the token to be valid for after its creation set in the `timestamp` field.
    ///
    /// If the TTL field is set to 0, then the expiration check is omitted.
    /// By default it is set to 0 when using `Branca::new(&key)` method.
    ttl: u32,
    /// The creation time of the Branca token. If not specified manually, it is created
    /// given the current system time, each time `encode()` is called.
    ///
    /// This is used together with the `ttl` to check if the token has expired or not.
    timestamp: u32,
}

impl PartialEq for Branca {
    fn eq(&self, other: &Branca) -> bool {
        let key_eq: bool =
            orion::util::secure_cmp(self.key[..].as_ref(), other.key[..].as_ref()).is_ok();

        key_eq
            & (self.nonce == other.nonce)
            & (self.ttl == other.ttl)
            & (self.timestamp == other.timestamp)
    }
}

impl core::fmt::Debug for Branca {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "Branca {{ key: [SECRET VALUE], nonce: {:?}, ttl: {:?},
            timestamp: {:?} }}",
            self.nonce, self.ttl, self.timestamp
        )
    }
}

impl Branca {
    /// Create a new Branca struct with a specified key. The length of the key must be exactly 32 bytes.
    ///
    /// This panics if the current system time cannot be obtained.
    ///
    /// `key` - The key to be used for encrypting and decrypting the input.
    ///
    ///```rust
    /// extern crate getrandom;
    /// extern crate branca;
    /// use branca::Branca;
    ///
    /// fn main() {
    ///        let mut key = [0u8; 32];
    ///        getrandom::fill(&mut key).unwrap();
    ///        let token = Branca::new(&key);
    /// }
    ///```
    pub fn new(key: &[u8]) -> Result<Branca, BrancaError> {
        // Check the key length before going any further.
        if key.len() != CHACHA_KEYSIZE {
            return Err(BrancaError::BadKeyLength);
        }

        Ok(Branca {
            key: key.to_vec(),
            nonce: Vec::new(),
            ttl: 0,
            timestamp: 0,
        })
    }

    /// The Branca key used for encrypting the message.
    pub fn key(self) -> Vec<u8> {
        self.key
    }
    /// The Branca nonce used with the key for encrypting the message.
    /// A new nonce is generated each time `encode()` is called. If `encode()`
    /// hasn't been called yet, this returns an empty vector.
    pub fn nonce(self) -> Vec<u8> {
        self.nonce
    }
    /// The Time-To-Live (TTL) field used for setting the expiration time of the
    /// generated Branca token in seconds.
    pub fn ttl(self) -> u32 {
        self.ttl
    }
    /// The timestamp determines the validity of the token upon creation.
    /// When used with the TTL, the expiration time is determined simply by:
    /// `exp_timestamp = (timestamp + ttl)`
    ///
    /// If this hasn't been specified manually, or `encode()` hasn't been called yet,
    /// this returns `0`.
    ///
    /// If the token has been set with a TTL, the decoder checks the validity of the token
    /// and any timestamp set before the future_time is valid, otherwise it is expired.
    pub fn timestamp(self) -> u32 {
        self.timestamp
    }
    /// Sets the key used for encryption and decryption.
    ///
    /// Must be 32 bytes in length.
    pub fn set_key(&mut self, key: Vec<u8>) -> &mut Self {
        self.key = key;
        self
    }
    /// Sets the TTL used for token expiration.
    pub fn set_ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = ttl;
        self
    }
    /// Sets the timestamp key used for validating with the TTL.
    pub fn set_timestamp(&mut self, timestamp: u32) -> &mut Self {
        self.timestamp = timestamp;
        self
    }
    /// Encodes the message with the created Branca struct.
    ///
    /// This panics if unable to securely generate random bytes or if unable to obtain current system time.
    ///
    /// If the `timestamp` hasn't been set, the current system time is used. If `timestamp` has been set and is not `0`,
    /// that value is used for all tokens created with this function (until changed).
    ///
    /// The contents of the message can be of any arbitrary sequence of bytes, ie. text, JSON, Protobuf, JWT or a MessagePack, etc.
    ///
    /// `message` - The data to be encoded as a Branca token.
    ///
    /// # Example
    /// ```rust
    /// extern crate getrandom;
    /// extern crate branca;
    /// use branca::Branca;
    ///
    /// fn main() {
    ///     let mut key = [0u8; 32];
    ///     getrandom::fill(&mut key).unwrap();
    ///     let mut token = Branca::new(&key).unwrap();
    ///
    ///     let ciphertext = token.encode(b"Hello World!").unwrap();
    ///     // Branca token is now in 'ciphertext' as a String.
    /// }
    /// ```
    pub fn encode(&mut self, message: &[u8]) -> Result<String, BrancaError> {
        // A timestamp has not been manually set, so we create one automatically.
        let mut timestamp = self.timestamp;
        if timestamp == 0 {
            // Generate a timestamp instead of a zero supplied one.
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to obtain timestamp from system clock.");
            timestamp = ts.as_secs() as u32;
        }

        // Generate Nonce (24 bytes in length)
        let mut nonce = [0; XCHACHA_NONCESIZE];
        secure_rand_bytes(&mut nonce).unwrap();
        self.nonce = nonce.to_vec();

        encode_with_nonce(message, &self.key, &Nonce::from(nonce), timestamp)
    }

    /// Decodes a Branca token with the provided key in the struct.
    ///
    /// `ciphertext` - The input which is to be decrypted with the key found in the Branca struct.
    ///
    /// `ttl` - The time-to-live upon creation of the token with its timestamp in seconds.
    ///
    /// If the supplied ttl is set to 0, then the expiration check is omitted. It is recommended to
    /// set this if you want to check the timestamp of an incoming token generated by the client.
    ///
    ///# Example
    ///```rust
    /// extern crate getrandom;
    /// extern crate branca;
    /// use branca::Branca;
    ///
    /// fn main() {
    ///     let mut key = [0u8; 32];
    ///     getrandom::fill(&mut key).unwrap();
    ///
    ///     let mut token = Branca::new(&key).unwrap();
    ///     let crypted = token.encode(b"Hello World!").unwrap();
    ///     // Branca token is now in 'crypted' as a String.
    ///    
    ///     let decrypted = token.decode(crypted.as_str(), 3600);
    ///     let mut payload: Vec<u8> = Vec::new();
    ///
    ///     if decrypted.is_err() {
    ///       // Something went wrong here...
    ///     } else {
    ///       payload = decrypted.unwrap();
    ///      // payload now contains "Hello World!"
    ///     }
    /// }
    /// ```
    pub fn decode(&self, ciphertext: &str, ttl: u32) -> Result<Vec<u8>, BrancaError> {
        decode(ciphertext, &self.key, ttl)
    }
}

/// Encodes the message and returns a Branca Token as a String.
///
/// The contents of the message can be of any arbitrary sequence of bytes, ie. text, JSON, Protobuf, JWT or a MessagePack, etc.
///
/// `data` - The data to be encoded as a Branca token.
///
/// `key` - The key to use for encryption.
///
/// `timestamp` - The timestamp at which the token was created.
///
/// Note:
///
/// * The key must be 32 bytes in length, otherwise it returns a `BrancaError::BadKeyLength` Result.
///
/// * The generated nonce is 24 bytes in length, otherwise it returns a `BrancaError::BadNonceLength` Result.
///
/// * This function panics if unable to securely generate random bytes.
pub fn encode(data: &[u8], key: &[u8], timestamp: u32) -> Result<String, BrancaError> {
    // Use CSPRNG to generate a unique nonce.
    let n = Nonce::generate();

    encode_with_nonce(data, key, &n, timestamp)
}

fn encode_with_nonce(
    data: &[u8],
    key: &[u8],
    nonce: &Nonce,
    timestamp: u32,
) -> Result<String, BrancaError> {
    let sk: SecretKey = match SecretKey::from_slice(key) {
        Ok(key) => key,
        Err(UnknownCryptoError) => return Err(BrancaError::BadKeyLength),
    };

    // Version || Timestamp || Nonce
    let mut header = [0u8; 29];

    header[0] = VERSION;
    BigEndian::write_u32(&mut header[1..5], timestamp);
    header[5..29].copy_from_slice(nonce.as_ref());

    let mut buf_crypt = vec![0u8; data.len() + 16 + 29]; // 16 bytes for the Poly1305 Tag.
                                                         // The header is prepended to the ciphertext and tag.
    buf_crypt[..29].copy_from_slice(header.as_ref());

    match seal(
        &sk,
        nonce,
        data,
        Some(header.as_ref()),
        &mut buf_crypt[29..],
    ) {
        Ok(()) => (),
        Err(UnknownCryptoError) => return Err(BrancaError::EncryptFailed),
    };

    // Return payload encoded as base62.
    Ok(b62_encode(BASE62, buf_crypt.as_ref()))
}

/// Decodes a Branca token and returns the plaintext as a String.
///
/// `data` - The input which is to be decrypted with the user-supplied key.
///
/// `key` - The user-supplied key to use for decryption.
///
/// `ttl` - The time-to-live upon creation of the token with its timestamp in seconds.
///
/// If the supplied ttl is set to 0, then the expiration check is omitted. It is recommended to
/// set this if you want to check the timestamp of an incoming token generated by the client.
///
/// Note:
///
/// * The key must be 32 bytes in length, otherwise it returns a `BrancaError::BadKeyLength` Result.
///
/// * If the decryption fails, it returns a `BrancaError::DecryptFailed` Result.
///
/// * If the TTL is non-zero and the timestamp of the token is in the past, it is considered to be expired; returning a `BrancaError::ExpiredToken` Result.
///
/// * If the input is not in Base62 format, it returns a `BrancaError::InvalidBase62Token` Result.
///
/// * If adding TTL to the token timestamp results in an overflow, it returns a `BrancaError::OverflowingOperation` Result.
///
/// * This panics if the current system time cannot be obtained.
pub fn decode(data: &str, key: &[u8], ttl: u32) -> Result<Vec<u8>, BrancaError> {
    // Extract timestamp & payload.
    let (timestamp, buf_crypt) = decode_with_timestamp(data, key)?;

    // TTL check to determine if the token has expired.
    if ttl != 0 {
        let future = match timestamp.checked_add(ttl) {
            Some(value) => value as u64,
            None => return Err(BrancaError::OverflowingOperation),
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to obtain timestamp from system clock.")
            .as_secs();
        if future < now {
            return Err(BrancaError::ExpiredToken);
        }
    }

    // Return the plaintext.
    Ok(buf_crypt)
}

/// Decodes a Branca token and returns the timestamp and plaintext as a tuple.
/// This is the underlying function used by `decode()` to extract the timestamp
/// and the plaintext from the token.
/// This function is useful if you want to extract the timestamp without checking the TTL (or implement your own TTL logic).
/// 
/// `data` - The input which is to be decrypted with the user-supplied key.
/// 
/// `key` - The user-supplied key to use for decryption.
/// 
/// Note:
/// 
/// * The key must be 32 bytes in length, otherwise it returns a `BrancaError::BadKeyLength` Result.
/// 
/// * If the decryption fails, it returns a `BrancaError::DecryptFailed` Result.
/// 
/// * If the input is not in Base62 format, it returns a `BrancaError::InvalidBase62Token` Result.
pub fn decode_with_timestamp(
    data: &str,
    key: &[u8],
) -> Result<(u32, Vec<u8>), BrancaError> {
    let sk: SecretKey = match SecretKey::from_slice(key) {
        Ok(key) => key,
        Err(UnknownCryptoError) => return Err(BrancaError::BadKeyLength),
    };

    if data.len() < 61 {
        return Err(BrancaError::InvalidBase62Token);
    }

    let decoded_data = match b62_decode(BASE62, data) {
        Ok(decoded) => decoded,
        Err(_) => return Err(BrancaError::InvalidBase62Token),
    };

    // After we have decoded the data, the branca token is now represented
    // by the following layout below:

    // Branca( header[0..29] + ciphertext[29..] )
    // Version (&u8) || Timestamp (u32) || Nonce ([u8;24]) || Ciphertext (&[u8]) || Tag ([u8:16])

    // We then obtain the header, ciphertext, version and timestamp with this layout.

    // Check if there is a version mismatch.
    if decoded_data[0] != VERSION {
        return Err(BrancaError::InvalidTokenVersion);
    }

    let header = &decoded_data[0..29];
    let n: Nonce = Nonce::from_slice(decoded_data[5..29].as_ref()).unwrap();
    let mut buf_crypt = vec![0u8; decoded_data.len() - 16 - 29];

    match open(
        &sk,
        &n,
        decoded_data[29..].as_ref(),
        Some(header),
        &mut buf_crypt,
    ) {
        Ok(()) => (),
        Err(orion::errors::UnknownCryptoError) => return Err(BrancaError::DecryptFailed),
    };

    let timestamp: u32 = BigEndian::read_u32(&decoded_data[1..5]);

    Ok((timestamp, buf_crypt))
}

#[cfg(test)]
mod unit_tests {

    use super::*;

    mod json_test_vectors {
        use super::*;
        use std::fs::File;
        use std::io::BufReader;

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize, Debug)]
        struct TestFile {
            version: String,
            numberOfTests: u32,
            testGroups: Vec<TestGroup>,
        }

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize, Debug)]
        struct TestGroup {
            testType: String,
            tests: Vec<TestVector>,
        }

        #[allow(non_snake_case)]
        #[derive(Serialize, Deserialize, Debug)]
        struct TestVector {
            id: u32,
            comment: String,
            key: String,
            nonce: Option<String>,
            timestamp: u32,
            token: String,
            msg: String,
            isValid: bool,
        }

        fn parse_hex(data: &str) -> Vec<u8> {
            match data {
                "" => vec![0u8; 0],
                "80" => b"\x80".to_vec(),
                _ => hex::decode(data).unwrap(),
            }
        }

        #[test]
        pub fn run_test_vectors() {
            let file = File::open("test_data/test_vectors.json").unwrap();
            let reader = BufReader::new(file);
            let tests: TestFile = serde_json::from_reader(reader).unwrap();

            let mut tests_run = 0;
            for test_group in tests.testGroups.iter() {
                for test in test_group.tests.iter() {
                    if test_group.testType == "encoding" {
                        debug_assert!(test.nonce.is_some());

                        if test.isValid {
                            let nonce = Nonce::from_slice(&parse_hex(test.nonce.as_ref().unwrap()))
                                .unwrap();

                            let res = encode_with_nonce(
                                &parse_hex(&test.msg),
                                &parse_hex(&test.key),
                                &nonce,
                                test.timestamp,
                            )
                            .unwrap();

                            assert_eq!(res, test.token);
                            assert_eq!(
                                decode(&test.token, &parse_hex(&test.key), 0).unwrap(),
                                parse_hex(&test.msg)
                            );

                            tests_run += 1;
                        }

                        if !test.isValid {
                            let nonce = Nonce::from_slice(&parse_hex(test.nonce.as_ref().unwrap()));

                            if nonce.is_err() {
                                tests_run += 1;
                                continue;
                            }

                            let res = encode_with_nonce(
                                &parse_hex(&test.msg),
                                &parse_hex(&test.key),
                                &nonce.unwrap(),
                                test.timestamp,
                            );

                            assert!(res.is_err());
                            tests_run += 1;
                        }
                    }

                    if test_group.testType == "decoding" {
                        debug_assert!(test.nonce.is_none());

                        let res = decode(
                            &test.token,
                            &parse_hex(&test.key),
                            0, // Not a part of test vectors
                        );

                        assert_eq!(test.isValid, res.is_ok());
                        tests_run += 1;
                    }
                }
            }

            assert_eq!(tests_run, tests.numberOfTests);
        }
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct JSONTest {
        a: String,
        b: bool,
    }

    #[test]
    pub fn test_encode_builder() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut token = Branca::new(key).unwrap();
        let ciphertext = token.set_timestamp(123206400).encode(b"Test");
        assert!(ciphertext.is_ok());
    }

    #[test]
    pub fn test_decode() {
        let ciphertext =
            "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let key = b"supersecretkeyyoushouldnotcommit";
        let ttl = 0;

        assert_eq!(decode(ciphertext, key, ttl).unwrap(), b"Hello world!");
    }

    #[test]
    pub fn test_encode_and_decode() {
        let message = b"Hello world!";
        let timestamp = 123206400;
        let branca_token = encode(message, b"supersecretkeyyoushouldnotcommit", timestamp).unwrap();

        assert_eq!(
            decode(
                branca_token.as_str(),
                b"supersecretkeyyoushouldnotcommit",
                0
            )
            .unwrap(),
            b"Hello world!"
        );
    }

    #[test]
    pub fn test_encode_and_decode_random_nonce() {
        let message = b"Hello world!";
        let timestamp = 123206400;
        let branca_token = encode(message, b"supersecretkeyyoushouldnotcommit", timestamp).unwrap();

        assert_eq!(
            decode(
                branca_token.as_str(),
                b"supersecretkeyyoushouldnotcommit",
                0
            )
            .unwrap(),
            b"Hello world!"
        );
    }

    #[test]
    pub fn test_encode_and_decode_json() {
        let literal_json = json!({ "a": "some string", "b": false });
        let message = literal_json.to_string();
        let timestamp = 123206400;
        let branca_token = encode(
            message.as_bytes(),
            b"supersecretkeyyoushouldnotcommit",
            timestamp,
        )
        .unwrap();
        let json = decode(
            branca_token.as_str(),
            b"supersecretkeyyoushouldnotcommit",
            0,
        )
        .unwrap();
        let serialized_json: JSONTest =
            serde_json::from_str(&String::from_utf8_lossy(&json)).unwrap();

        assert_eq!(serialized_json.a, "some string");
        assert!(!serialized_json.b);
    }

    #[test]
    pub fn test_encode_and_decode_json_literal() {
        let message = r#"{
                 "a":"some string",
                 "b":false
          }"#;
        let timestamp = 123206400;
        let branca_token = encode(
            message.as_bytes(),
            b"supersecretkeyyoushouldnotcommit",
            timestamp,
        )
        .unwrap();
        let json = decode(
            branca_token.as_str(),
            b"supersecretkeyyoushouldnotcommit",
            0,
        )
        .unwrap();
        let serialized_json: JSONTest =
            serde_json::from_str(&String::from_utf8_lossy(&json)).unwrap();

        assert_eq!(serialized_json.a, "some string");
        assert!(!serialized_json.b);
    }

    #[test]
    pub fn test_encode_and_decode_builder() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut token = Branca::new(key).unwrap();
        let ciphertext = token.encode(b"Test").unwrap();
        let payload = token.decode(ciphertext.as_str(), 0).unwrap();

        assert_eq!(payload, b"Test");
    }

    #[test]
    pub fn test_encode_and_decode_builder_with_exp_ttl() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut token = Branca::new(key).unwrap();
        let ciphertext = token.set_timestamp(123206400).encode(b"Test").unwrap();
        let payload = token.decode(ciphertext.as_str(), 0);

        if let Err(e) = payload {
            assert_eq!(e, BrancaError::ExpiredToken)
        }
    }

    #[test]
    pub fn test_expired_ttl() {
        let ciphertext =
            "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let key = b"supersecretkeyyoushouldnotcommit";
        let ttl = 3600;
        let message = decode(ciphertext, key, ttl);

        if let Err(e) = message {
            assert_eq!(e, BrancaError::ExpiredToken)
        }
    }

    #[test]
    pub fn test_decryption_fail() {
        let ciphertext =
            "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let key = b"supersecretkeyyoushouldnotcommi.";
        let ttl = 0;
        let branca_token = decode(ciphertext, key, ttl);

        if let Err(e) = branca_token {
            assert_eq!(e, BrancaError::DecryptFailed)
        }
    }

    #[test]
    pub fn test_base62_fail() {
        let ciphertext = "875GH233T7IYrxtgXxlQBYiFo";
        let key = b"supersecretkeyyoushouldnotcommit";
        let ttl = 0;
        let branca_token = decode(ciphertext, key, ttl);

        if let Err(e) = branca_token {
            assert_eq!(e, BrancaError::InvalidBase62Token)
        }
    }

    #[test]
    pub fn test_bad_key() {
        let key = b"supersecretkey";
        let message = b"Hello world!";
        let timestamp = 123206400;
        let branca_token = encode(message, key, timestamp);

        if let Err(e) = branca_token {
            assert_eq!(e, BrancaError::BadKeyLength)
        }
    }

    #[test]
    pub fn test_version_mismatch() {
        let ciphertext =
            "005GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let key = b"supersecretkeyyoushouldnotcommit";
        let ttl = 0;
        let branca_token = decode(ciphertext, key, ttl);

        if let Err(e) = branca_token {
            assert_eq!(e, BrancaError::InvalidTokenVersion)
        }
    }

    #[test]
    pub fn test_modified_timestamp_returns_bad_tag() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut ctx = Branca::new(key).unwrap();
        ctx.timestamp = 0; // Make sure current gets used.

        let token = ctx.encode(b"Test").unwrap();
        let mut decoded = b62_decode(BASE62, &token).unwrap();

        // 651323084: Some day in 1990
        BigEndian::write_u32(&mut decoded[1..5], 651323084);

        assert_eq!(
            decode(&b62_encode(BASE62, &decoded), key, 1000).unwrap_err(),
            BrancaError::DecryptFailed
        );
    }

    #[test]
    pub fn test_no_panic_on_display() {
        // to_string() should not panic.
        // See: https://github.com/return/branca/issues/14
        let _tostr = BrancaError::InvalidTokenVersion.to_string();
    }

    #[test]
    pub fn test_empty_payload_encode_decode() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut ctx = Branca::new(key).unwrap();
        assert!(ctx.encode(b"").is_ok());

        // Empty token cross-checked with pybranca
        let decoded = ctx
            .decode(
                "4tGtt5wP5DCXzPhNbovMwEg9saksXSdmhvFbdrZrQjXEWf09BtuAK1wG5lpG0",
                0,
            )
            .unwrap();
        assert_eq!(b"", &decoded[..]);
    }

    #[test]
    pub fn test_non_utf8_encode_decode() {
        // See: https://github.com/return/branca/issues/10
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut ctx = Branca::new(key).unwrap();
        let own_token = ctx.encode(b"\x80").unwrap();
        assert_eq!(b"\x80", &ctx.decode(own_token.as_str(), 0).unwrap()[..]);

        let decoded = ctx
            .decode(
                "K9i9jp23WMENUOulBifHPEnfBp67LfQBE3wYBCPSCu2uTBEeFHwGJZfH8DOTa1",
                0,
            )
            .unwrap();
        assert_eq!(b"\x80", &decoded[..]);
    }

    #[test]
    pub fn test_correct_err_on_invalid_base62() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut token = encode(b"Hello world!", key, 0).unwrap();
        token.push('_');

        assert_eq!(
            decode(&token, key, 0).unwrap_err(),
            BrancaError::InvalidBase62Token
        );
    }

    #[test]
    pub fn test_builder_nonce_is_correctly_used() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let mut ctx = Branca::new(key).unwrap();
        assert!(ctx.nonce.is_empty());

        let token = ctx.encode(b"").unwrap();
        assert!(!ctx.nonce.is_empty());

        // Ensure the builder's nonce is used
        let raw_token = b62_decode(BASE62, &token).unwrap();
        let raw_token_nonce = &raw_token[5..29];
        assert_eq!(raw_token_nonce, &ctx.nonce[..]);

        // Ensure a new nonce is generated when calling encode
        let token_again = ctx.encode(b"").unwrap();
        let raw_token_again = b62_decode(BASE62, &token_again).unwrap();
        let raw_token_nonce_again = &raw_token_again[5..29];
        assert_eq!(raw_token_nonce_again, &ctx.nonce[..]);
        assert_ne!(raw_token_nonce_again, raw_token_nonce);
    }

    #[test]
    pub fn test_error_on_overflowing_timestamp() {
        let key = b"supersecretkeyyoushouldnotcommit";
        let token = encode(b"", key, 4294967295).unwrap();

        assert_eq!(
            decode(&token, key, 1).unwrap_err(),
            BrancaError::OverflowingOperation
        );
    }
}
