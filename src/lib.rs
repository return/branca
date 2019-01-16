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

extern crate byteorder;
extern crate base_x;
extern crate chacha20_poly1305_aead;

pub mod errors;

mod hchacha20;

use byteorder::*;
use base_x::{encode as b62_encode, decode as b62_decode};
use self::errors::Error as BrancaError;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use ring::rand::{SystemRandom, SecureRandom};

// Branca magic byte.
const VERSION: u8 = 0xBA;
// Branca nonce bytes.
const NONCE_BYTES: usize = 24;
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
    pub fn new (key: &[u8]) -> Result<Branca, BrancaError> {

        // Check the key length before going any further.
        if key.len() != 32 {
            return Err(BrancaError::BadKeyLength);
        }

        // Generate Nonce (24 bytes in length)
        let mut nonce = vec![0; 24];
        SystemRandom::new().fill(nonce.as_mut()).unwrap();

        // Generate a timestamp instead of a zero supplied one.
        let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Failed to obtain timestamp from system clock.");
        let timestamp = ts.as_secs() as u32;

        Ok(Branca {
            key: key.to_vec(),
            nonce,
            ttl: 0,
            timestamp
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
            let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Failed to obtain timestamp from system clock.");
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
    if nonce.len() != 24 {
      return Err(BrancaError::BadNonceLength);
    }

    // Check the key length before going any further.
    if key.len() != 32 {
      return Err(BrancaError::BadKeyLength);
    }

    // We can now create a Key and Nonce struct from the inputs.
    let mut key_derv = [0u8; 32];
    
    let mut nonce_bytes = [0u8; NONCE_BYTES];

    key_derv.copy_from_slice(key);

    nonce_bytes.copy_from_slice(nonce);

    // The nonce is now appended to the timestamp in a vector.
    let mut time_bytes = vec![0x0; 4];

    BigEndian::write_u32(&mut time_bytes, timestamp);
    time_bytes.append(&mut nonce.to_vec());

    // We append the version header to the timestamp vector.
    let mut version_header = vec![VERSION];
    version_header.append(&mut time_bytes);

    // The ChaCha20-Poly1305 crate doesn't yet support extended
    // nonces, needed to construct a Branca token. ChaCha20-Poly1305
    // requires a 12 byte nonce whereas XChaCha20-Poly1305 requires a
    // 24 byte nonce.

    // Since we must use a 24 byte nonce for generating branca tokens,
    // we can first use a HChaCha20 construction to encrypt the key
    // using the first half of the nonce with the key and encrypting the
    // plaintext using the last 16 bytes of the nonce with the output of the
    // HChaCha20 construct; giving us XChaCha20.

    // Create the first part of the nonce 16 bytes in length required by HChaCha20.

    let mut derv_nonce_1 = [0u8; 16];
    derv_nonce_1.copy_from_slice(&nonce_bytes[..16]);

    // Encrypt the key and the 16 byte nonce with HChaCha20.
    // We use this as the key for the ChaCha20-Poly1305 encryption method.

    // More on the construction of XChaCha20 can be found here.
    // https://tools.ietf.org/html/draft-arciszewski-xchacha-00#section-2.3.1

    let part_crypted = hchacha20::hchacha20(&key_derv, &derv_nonce_1);

    // We now copy the last 12 bytes of the nonce by skipping the first
    // 4 bytes of the derived nonce. The nonce now contains the last 12 bytes.
    let mut derv_nonce_2 =[0u8; 12];
    derv_nonce_2[4..].copy_from_slice(&nonce_bytes[16..]);

    let mut buf_crypt = Vec::with_capacity(data.len());

    // Encrypt the payload with ChaCha20-Poly1305 AEAD (de-attached mode)
    // We return the tag to be used later to construct the rest of the branca token.

    // Use the version header as the authenticated additional data.
    let aead_tag = chacha20_poly1305_aead::encrypt(&part_crypted, &derv_nonce_2, &version_header, data.as_bytes(), &mut buf_crypt).unwrap();

    // Append the tag to the ciphertext saved into the buffer.
    buf_crypt.append(&mut aead_tag.to_vec());

    // The ciphertext is appended to the version header.
    version_header.append(&mut buf_crypt);

    // Our payload is now encoded into base62. 
    let b62_enc = b62_encode(BASE62, version_header.as_slice());
    
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
    if key.len() != 32 {
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

    let header = &decoded_data[0..29];
    let ciphertext = &decoded_data[29..(decoded_data.len() - 16)];
    let version = vec![header[0]];
    let timestamp = BigEndian::read_u32(&header[1..5]);
    let tag = &decoded_data[(decoded_data.len() - 16)..decoded_data.len()];

    // Create the key given from the input.
    let mut key_bytes = [0u8; 32];
    
    key_bytes.copy_from_slice(key);

    // Extract the 24 byte nonce in the header starting
    // from the first 6 bytes.
    let mut nonce_n = [0u8; NONCE_BYTES];
    nonce_n.copy_from_slice(&header[5..]);

    let mut derv_nonce_1 = [0u8; 16];

    // Copy the first 16 bytes from the 24 byte nonce.
    derv_nonce_1.copy_from_slice(&nonce_n[..16]);

    // Encrypt the first 16 bytes of the nonce with our key required by HChaCha20.
    let part_crypted = hchacha20::hchacha20(&key_bytes, &derv_nonce_1);

    let mut derv_nonce_2 =[0u8; 12];

    // Copy the rest of the 12 bytes from the 24 byte nonce.
    // We must offset from the first 4 bytes to later use
    // the remaining 12 bytes later for the ChaCha20 construction.
    derv_nonce_2[4..].copy_from_slice(&nonce_n[16..]);

    // The full nonce is now appended to the timestamp in a vector.
    let mut time_bytes = vec![0x0; 4];
    BigEndian::write_u32(&mut time_bytes, timestamp);
    time_bytes.append(&mut Vec::from(&header[5..]));

    // We now append the version header to the timestamp vector.
    let mut version_header = vec![VERSION];
    version_header.append(&mut time_bytes);

    // Check if there is a version mismatch.
    if version.as_slice()[0] != VERSION {
       return Err(BrancaError::InvalidTokenVersion);
    }

    let mut buf_crypt = Vec::with_capacity(ciphertext.len());

    // Retrieve the plaintext using ChaCha20-Poly1305 AEAD (de-attached mode)
    // We use the output of HChaCha20 (part_crypted) as the key with the
    // rest of the 16 byte nonce; i.e decrypting using XChaCha20 instead of ChaCha20.
    let decrypted = chacha20_poly1305_aead::decrypt(&part_crypted, &derv_nonce_2, &version_header, &ciphertext, &tag, &mut buf_crypt);

     if decrypted.is_err() {
         return Err(BrancaError::DecryptFailed);
     }

    // TTL check to determine if the token has expired.
     if ttl != 0 {
         let future = u64::from(timestamp + ttl);
         let time_now = SystemTime::now();
         let ts_seconds = time_now.duration_since(UNIX_EPOCH).expect("Failed to obtain timestamp from system clock.");
         let timestamp_now = ts_seconds.as_secs();
         if future < timestamp_now {
             return Err(BrancaError::ExpiredToken);
         }
    }

    // Return the plaintext.
    return Ok(String::from_utf8(buf_crypt).unwrap());
}