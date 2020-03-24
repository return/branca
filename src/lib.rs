/*!
Branca - Authenticated and Encrypted API tokens using modern cryptography.

This crate is a Pure-Rust implementation of [Branca](https://branca.io)
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

use branca::Branca;

fn main() {
    let key = b"supersecretkeyyoushouldnotcommit".to_vec();
    let token = Branca::new(&key).unwrap();
    let ciphertext = token.encode("Hello World!").unwrap();

    let payload = token.decode(ciphertext.as_str(), 0).unwrap();
    println!("{}", payload); // "Hello World!"
}
```

You can also decide to set the other fields in the token before encoding it if you want to since
this is a builder method.


```rust
extern crate branca;

use branca::Branca;

fn main() {
    let key = b"supersecretkeyyoushouldnotcommit".to_vec();
    let mut token = Branca::new(&key).unwrap();

    // You are able to use the builder to set the timestamp, ttL and the key.
    // However, the nonce cannot be set, as that is a security risk for
    // nonce-reuse misuse.

    // All properties inside of the token can be retrieved.

    let ciphertext = token
                      .set_timestamp(1234567890)
                      .set_key(key)
                      .set_ttl(300);
                      //.encode("Hello World!").unwrap();

    let timestamp = token.timestamp(); // 1234567890
}
```

It is also possible to directly encode and decode functions without using the builder function.

Please note that Branca uses [Orion](https://github.com/brycx/orion) to generate secure random nonces
when using the encode() and builder methods. By default, Branca does not allow setting the nonce directly
since that there is a risk that it can be reused by the user which is a foot-gun.

```rust
extern crate branca;

use branca::{encode, decode};

let key = b"supersecretkeyyoushouldnotcommit".to_vec();
let token = encode("Hello World!", &key, 123206400).unwrap();
// token = "875G...p0a"

let ttl = 3600;
// The token will expire at timestamp + ttl
let payload = decode(token.as_str(), &key, 0).unwrap();

println!("{}", payload);
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
    nonce: Vec<u8>,
    /// The Time-to-live field (TTL) to set the number of seconds
    /// for the token to be valid for after its creation set in the `timestamp` field.
    ///
    /// If the TTL field is set to 0, then the expiration check is omitted.
    /// By default it is set to 0 when using `Branca::new(&key)` method.
    ttl: u32,
    /// The creation time of the Branca token.
    ///
    /// This is used together with the `ttl` to check if the token has expired or not.
    timestamp: u32,
}

impl PartialEq for Branca {
    fn eq(&self, other: &Branca) -> bool {
        let key_eq: bool =
            orion::util::secure_cmp(self.key[..].as_ref(), other.key[..].as_ref()).is_ok();

        (key_eq
            & (self.nonce == other.nonce)
            & (self.ttl == other.ttl)
            & (self.timestamp == other.timestamp))
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
    /// `key` - The key to be used for encrypting and decrypting the input.
    ///
    ///```rust
    /// extern crate branca;
    /// use branca::Branca;
    ///
    /// fn main() {
    ///        let key = b"supersecretkeyyoushouldnotcommit".to_vec();
    ///        let token = Branca::new(&key);
    /// }
    ///```
    pub fn new(key: &[u8]) -> Result<Branca, BrancaError> {
        // Check the key length before going any further.
        if key.len() != CHACHA_KEYSIZE {
            return Err(BrancaError::BadKeyLength);
        }

        // Generate Nonce (24 bytes in length)
        let mut nonce = vec![0; XCHACHA_NONCESIZE];
        secure_rand_bytes(&mut nonce).unwrap();

        // Generate a timestamp instead of a zero supplied one.
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to obtain timestamp from system clock.")
            .as_nanos() as u32;

        Ok(Branca {
            key: key.to_vec(),
            nonce,
            ttl: 0,
            timestamp,
        })
    }

    /// The Branca key used for encrypting the message.
    pub fn key(self) -> Vec<u8> {
        self.key
    }
    /// The Branca nonce used with the key for encrypting the message.
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
    /// The contents of the message can be of any arbitrary sequence of bytes, ie. text, JSON, Protobuf, JWT or a MessagePack, etc.
    ///
    /// `message` - The data to be encoded as a Branca token.
    ///
    /// # Example
    /// ```rust
    /// extern crate branca;
    /// use branca::Branca;
    ///
    /// fn main() {
    ///     let key = b"supersecretkeyyoushouldnotcommit".to_vec();
    ///     let token = Branca::new(&key).unwrap();
    ///
    ///     let ciphertext = token.encode("Hello World!").unwrap();
    ///     // Branca token is now in 'ciphertext' as a String.
    /// }
    /// ```
    pub fn encode(&self, message: &str) -> Result<String, BrancaError> {
        let mut timestamp = self.timestamp;
        if timestamp == 0 {
            // Generate a timestamp instead of a zero supplied one.
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to obtain timestamp from system clock.");
            timestamp = ts.as_secs() as u32;
        }
        let crypted = encode(message, &self.key, timestamp);

        Ok(crypted.unwrap())
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
    /// extern crate branca;
    /// use branca::Branca;
    ///
    /// fn main() {
    ///     let token = Branca::new(&b"supersecretkeyyoushouldnotcommit".to_vec()).unwrap();
    ///     let crypted = token.encode("Hello World!").unwrap();
    ///     // Branca token is now in 'crypted' as a String.
    ///    
    ///     let decrypted = token.decode(crypted.as_str(), 3600);
    ///     let mut payload: String  = Default::default();
    ///
    ///     if decrypted.is_err() {
    ///       // Something went wrong here...
    ///     } else {
    ///       payload = decrypted.unwrap();
    ///      // payload now contains "Hello World!"
    ///     }
    /// }
    /// ```
    pub fn decode(&self, ciphertext: &str, ttl: u32) -> Result<String, BrancaError> {
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
pub fn encode(data: &str, key: &[u8], timestamp: u32) -> Result<String, BrancaError> {
    let sk: SecretKey = match SecretKey::from_slice(key) {
        Ok(key) => key,
        Err(UnknownCryptoError) => return Err(BrancaError::BadKeyLength),
    };

    // Use CSPRNG to generate a unique nonce.
    let n = Nonce::generate();
    // Version || Timestamp || Nonce
    let mut header = [0u8; 29];

    header[0] = VERSION;
    BigEndian::write_u32(&mut header[1..5], timestamp);
    header[5..29].copy_from_slice(n.as_ref());

    let mut buf_crypt = vec![0u8; data.len() + 16 + 29]; // 16 bytes for the Poly1305 Tag.
                                                         // The header is prepended to the ciphertext and tag.
    buf_crypt[..29].copy_from_slice(header.as_ref());

    match seal(
        &sk,
        &n,
        data.as_bytes(),
        Some(header.as_ref()),
        &mut buf_crypt[29..],
    ) {
        Ok(()) => (),
        Err(UnknownCryptoError) => return Err(BrancaError::EncryptFailed),
    };

    // Our payload is now encoded into base62.
    let b62_enc = b62_encode(BASE62, buf_crypt.as_ref());

    // Return the branca token as a string.
    Ok(b62_enc)
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
/// * If the TTL is non-zero and the timestamp of the token is in the past. It is considered to be expired; returning a `BrancaError::ExpiredToken` Result.
///
/// * If the input is not in Base62 format, it returns a `BrancaError::InvalidBase62Token` Result.
pub fn decode(data: &str, key: &[u8], ttl: u32) -> Result<String, BrancaError> {
    let sk: SecretKey = match SecretKey::from_slice(key) {
        Ok(key) => key,
        Err(UnknownCryptoError) => return Err(BrancaError::BadKeyLength),
    };

    if data.len() < 62 {
        return Err(BrancaError::InvalidBase62Token);
    }

    let decoded_data = b62_decode(BASE62, &data).expect("Base62 token is invalid.");

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
    let timestamp: u32 = BigEndian::read_u32(&decoded_data[1..5]);

    // TTL check to determine if the token has expired.
    if ttl != 0 {
        let future = timestamp.checked_add(ttl).expect("TTL too high.") as u64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to obtain timestamp from system clock.")
            .as_secs();
        if future < now {
            return Err(BrancaError::ExpiredToken);
        }
    }

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

    // Return the plaintext.
    Ok(String::from_utf8_lossy(&buf_crypt).into())
}

#[cfg(test)]
mod unit_tests {

    use super::*;

    #[derive(Serialize, Deserialize, Debug)]
    struct JSONTest {
        a: String,
        b: bool,
    }

    #[test]
    pub fn test_encode_builder() {
        let key = b"supersecretkeyyoushouldnotcommit".to_vec();
        let mut token = Branca::new(&key).unwrap();
        let ciphertext = token.set_timestamp(123206400).encode("Test");
        assert_eq!(ciphertext.is_ok(), true);
    }

    #[test]
    pub fn test_decode() {
        let ciphertext =
            "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
        let ttl = 0;

        assert_eq!(decode(ciphertext, &keygen, ttl).unwrap(), "Hello world!");
    }

    #[test]
    pub fn test_encode_and_decode() {
        let message = "Hello world!";
        let timestamp = 123206400;
        let branca_token = encode(
            message,
            &b"supersecretkeyyoushouldnotcommit".to_vec(),
            timestamp,
        )
        .unwrap();

        assert_eq!(
            decode(
                branca_token.as_str(),
                &b"supersecretkeyyoushouldnotcommit".to_vec(),
                0
            )
            .unwrap(),
            "Hello world!"
        );
    }

    #[test]
    pub fn test_encode_and_decode_random_nonce() {
        let message = "Hello world!";
        let timestamp = 123206400;
        let branca_token = encode(
            message,
            &b"supersecretkeyyoushouldnotcommit".to_vec(),
            timestamp,
        )
        .unwrap();

        assert_eq!(
            decode(
                branca_token.as_str(),
                &b"supersecretkeyyoushouldnotcommit".to_vec(),
                0
            )
            .unwrap(),
            "Hello world!"
        );
    }

    #[test]
    pub fn test_encode_and_decode_json() {
        let literal_json = json!({ "a": "some string", "b": false });
        let message = literal_json.to_string();
        let timestamp = 123206400;
        let branca_token = encode(
            message.as_str(),
            &b"supersecretkeyyoushouldnotcommit".to_vec(),
            timestamp,
        )
        .unwrap();
        let json = decode(
            branca_token.as_str(),
            &b"supersecretkeyyoushouldnotcommit".to_vec(),
            0,
        )
        .unwrap();
        let serialized_json: JSONTest = serde_json::from_str(json.as_str()).unwrap();

        assert_eq!(serialized_json.a, "some string");
        assert_eq!(serialized_json.b, false);
    }

    #[test]
    pub fn test_encode_and_decode_json_literal() {
        let message = r#"{
                 "a":"some string",
                 "b":false
          }"#;
        let timestamp = 123206400;
        let branca_token = encode(
            message,
            &b"supersecretkeyyoushouldnotcommit".to_vec(),
            timestamp,
        )
        .unwrap();
        let json = decode(
            branca_token.as_str(),
            &b"supersecretkeyyoushouldnotcommit".to_vec(),
            0,
        )
        .unwrap();
        let serialized_json: JSONTest = serde_json::from_str(json.as_str()).unwrap();

        assert_eq!(serialized_json.a, "some string");
        assert_eq!(serialized_json.b, false);
    }

    #[test]
    pub fn test_encode_and_decode_builder() {
        let key = b"supersecretkeyyoushouldnotcommit".to_vec();
        let token = Branca::new(&key).unwrap();
        let ciphertext = token.encode("Test").unwrap();
        let payload = token.decode(ciphertext.as_str(), 0).unwrap();

        assert_eq!(payload, "Test");
    }

    #[test]
    pub fn test_encode_and_decode_builder_with_exp_ttl() {
        let key = b"supersecretkeyyoushouldnotcommit".to_vec();
        let mut token = Branca::new(&key).unwrap();
        let ciphertext = token.set_timestamp(123206400).encode("Test").unwrap();
        let payload = token.decode(ciphertext.as_str(), 0);
        match payload {
            Err(e) => assert_eq!(e, BrancaError::ExpiredToken),
            Ok(_) => {}
        }
    }

    #[test]
    pub fn test_expired_ttl() {
        let ciphertext =
            "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
        let ttl = 3600;
        let message = decode(ciphertext, &keygen, ttl);

        match message {
            Err(e) => assert_eq!(e, BrancaError::ExpiredToken),
            Ok(_) => {}
        }
    }

    #[test]
    pub fn test_decryption_fail() {
        let ciphertext =
            "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let keygen = b"supersecretkeyyoushouldnotcommi.".to_vec();
        let ttl = 0;
        let branca_token = decode(ciphertext, &keygen, ttl);

        match branca_token {
            Err(e) => assert_eq!(e, BrancaError::DecryptFailed),
            Ok(_) => {}
        }
    }

    #[test]
    pub fn test_base62_fail() {
        let ciphertext = "875GH233T7IYrxtgXxlQBYiFo";
        let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
        let ttl = 0;
        let branca_token = decode(ciphertext, &keygen, ttl);

        match branca_token {
            Err(e) => assert_eq!(e, BrancaError::InvalidBase62Token),
            Ok(_) => {}
        }
    }

    #[test]
    pub fn test_bad_key() {
        let keygen = b"supersecretkey".to_vec();
        let message = "Hello world!";
        let timestamp = 123206400;
        let branca_token = encode(message, &keygen, timestamp);

        match branca_token {
            Err(e) => assert_eq!(e, BrancaError::BadKeyLength),
            Ok(_) => {}
        }
    }

    #[test]
    pub fn test_version_mismatch() {
        let ciphertext =
            "005GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
        let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
        let ttl = 0;
        let branca_token = decode(ciphertext, &keygen, ttl);

        match branca_token {
            Err(e) => assert_eq!(e, BrancaError::InvalidTokenVersion),
            Ok(_) => {}
        }
    }
}
