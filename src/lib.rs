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

```rust
875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a
```

The internal format of a Branca token looks like this:

```rust
Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)
```

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
    println("{}", payload); // "Hello World!"
}
```

You can also decide to set the other fields in the token before encoding it if you want to since
this is a builder method.

```rust
...
let ciphertext = token
                .set_timestamp(1234567890)
                .set_nonce(&nonce)
                .set_key(&key)
                .encode("Hello World!").unwrap();
...
```
It is also possible to directly encode and decode functions without using the builder function.
In this example I'm using ring for random number generation. You can use alternative CSRNG crates
such as the rand crate or sodiumoxide.
```rust
extern crate ring;

use branca::{encode, decode};
use ring::rand::SystemRandom;
...
let key = b"supersecretkeyyoushouldnotcommit".to_vec();
let mut nonce = vec![0; 24];
SystemRandom::new().fill(nonce.as_mut()).unwrap();

let token = encode("Hello World!", &keygen, &nonce, 123206400).unwrap();
// token = "875G...p0a"

let ttl = 3600;
// The token will expire at timestamp + ttl
let payload = decode(token.as_str(), &keygen, 0).unwrap();

println!({}, payload);
// payload = "Hello World!".
...
```
*/

extern crate base_x;
extern crate byteorder;
extern crate orion;

pub mod errors;

use self::errors::Error as BrancaError;
use base_x::{decode as b62_decode, encode as b62_encode};
use byteorder::*;
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
#[derive(Clone, PartialEq, Debug)]
pub struct Branca {
    /// The Branca Key which is exactly 32 bytes in length.
    key: Vec<u8>,
    /// The Branca Nonce which is exactly 24 bytes in length.
    nonce: Vec<u8>,
    /// The Time-to-live field (TTL) to set the number of milliseconds
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

impl Branca {
    /// Create a new Branca struct with a specified key. The length of the key must be exactly 32 bytes.
    ///
    /// `key` - The key to be used for encrypting and decrypting the input.
    ///
    ///```rust
    /// extern crate branca
    /// use branca::Branca
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
            timestamp: timestamp,
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
    /// generated Branca token in milliseconds (m/s).
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
    /// Sets the nonce used for encryption and decryption the input.
    ///
    /// Must be 24 bytes in length.
    pub fn set_nonce(&mut self, nonce: Vec<u8>) -> &mut Self {
        self.nonce = nonce;
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
    ///     let token = Branca::new(&b"supersecretkeyyoushouldnotcommit".to_vec());
    ///     let crypted = token.encode("Hello World!").unwrap();
    ///     // Branca token is now in 'crypted' as a String.
    /// }
    /// ```
    pub fn encode(&self, message: &str) -> Result<String, BrancaError> {
        let mut timestamp = self.timestamp;
        if timestamp <= 0 {
            // Generate a timestamp instead of a zero supplied one.
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to obtain timestamp from system clock.");
            timestamp = ts.as_secs() as u32;
        }
        let crypted = encode(message, &self.key, &self.nonce, timestamp);
        return Ok(crypted.unwrap());
    }
    /// Decodes a Branca token with the provided key in the struct.
    ///
    /// `ciphertext` - The input which is to be decrypted with the key found in the Branca struct.
    ///
    /// `ttl` - The time-to-live upon creation of the token with its timestamp in milliseconds (m/s)
    ///
    /// If the supplied ttl is set to 0, then the expiration check is omitted. It is recommended to
    /// set this if you want to check the timestamp of an incoming token generated by the client.
    ///
    ///# Example
    ///```rust
    ///extern crate branca;
    ///use branca::Branca;
    ///
    ///fn main() {
    ///    let token = Branca::new(&b"supersecretkeyyoushouldnotcommit".to_vec());
    ///    let crypted = token.encode("Hello World!").unwrap();
    ///    // Branca token is now in 'crypted' as a String.
    ///    
    ///    let decrypted = token.decode(crypted.as_str(), 3600);
    ///    let mut :String payload = Default::default();
    ///
    ///    if decrypted.is_err() {
    ///       // Something went wrong here...
    ///    } else {
    ///      payload = decrypted.unwrap();
    ///     // payload now contains "Hello World!"
    ///   }
    ///}
    /// ```
    pub fn decode(&self, ciphertext: &str, ttl: u32) -> Result<String, BrancaError> {
        return decode(ciphertext, &self.key, ttl);
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
/// `nonce` - The nonce to be used for encryption.
///
/// `timestamp` - The timestamp at which the token was created.
///
/// Note:
///
/// * The key must be 32 bytes in length, otherwise it returns a `BrancaError::BadKeyLength` Result.
///
/// * The nonce must be 24 bytes in length, otherwise it returns a `BrancaError::BadNonceLength` Result.
pub fn encode(data: &str, key: &[u8], nonce: &[u8], timestamp: u32) -> Result<String, BrancaError> {
    // Check the nonce length before going any further.
    if nonce.len() != XCHACHA_NONCESIZE {
        return Err(BrancaError::BadNonceLength);
    }

    // Check the key length before going any further.
    if key.len() != CHACHA_KEYSIZE {
        return Err(BrancaError::BadKeyLength);
    }

    // unwrap() cannot panic due to above length validation.
    let sk: SecretKey = SecretKey::from_slice(key).unwrap();
    let n: Nonce = Nonce::from_slice(nonce).unwrap();

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
        Some(&header),
        &mut buf_crypt[29..],
    ) {
        Ok(()) => (),
        Err(orion::errors::UnknownCryptoError) => return Err(BrancaError::EncryptFailed),
    };

    // Our payload is now encoded into base62.
    let b62_enc = b62_encode(BASE62, buf_crypt.as_ref());

    // Return the branca token as a string.
    return Ok(b62_enc);
}

/// Decodes a Branca token and returns the plaintext as a String.
///
/// `data` - The input which is to be decrypted with the user-supplied key.
///
/// `key` - The user-supplied key to use for decryption.
///
/// `ttl` - The time-to-live upon creation of the token with its timestamp in milliseconds (m/s).
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
    // The key must be 32 bytes in size.
    if key.len() != CHACHA_KEYSIZE {
        return Err(BrancaError::BadKeyLength);
    }

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
        let future = timestamp + ttl;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Failed to obtain timestamp from system clock.")
            .as_nanos() as u32;
        if future < now {
            return Err(BrancaError::ExpiredToken);
        }
    }

    // Create the key given from the input.
    let sk: SecretKey = SecretKey::from_slice(key).unwrap();
    let n: Nonce = Nonce::from_slice(decoded_data[5..29].as_ref()).unwrap();

    let mut buf_crypt = vec![0u8; decoded_data.len() - 16 - 29];

    match open(
        &sk,
        &n,
        decoded_data[29..].as_ref(),
        Some(header.as_ref()),
        &mut buf_crypt,
    ) {
        Ok(()) => (),
        Err(orion::errors::UnknownCryptoError) => return Err(BrancaError::DecryptFailed),
    };

    // Return the plaintext.
    return Ok(String::from_utf8_lossy(&buf_crypt).into());
}
