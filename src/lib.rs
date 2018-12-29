extern crate byteorder;
extern crate base_x;
extern crate chacha20_poly1305_aead;

pub mod hchacha20;
pub mod errors;

use byteorder::*;
use base_x::{encode as b62_encode, decode as b62_decode};
use errors::Error as BrancaError;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};

// Branca magic byte.
const VERSION: u8 = 0xBA;
// Branca nonce bytes.
const NONCE_BYTES: usize = 24;
// Base 62 alphabet.
const BASE62: &'static str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Branca builder
#[derive(Clone, PartialEq, Debug)]
pub struct Branca {
    key: Vec<u8>,
    nonce: Vec<u8>,
    ttl: u32,
    timestamp: u32,
}

impl Branca {
    pub fn new () -> Branca {
        Branca {
            key: Default::default(),
            nonce: Default::default(),
            ttl: Default::default(),
            timestamp: Default::default()
        }
    }
    pub fn key(&self) -> &Vec<u8> {
        &self.key
    }
    pub fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }
    pub fn ttl(&self) -> u32 {
        self.ttl
    }
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
    pub fn set_key(mut self, key: Vec<u8>) -> Self {
        self.key = key;
        self
    }
    pub fn set_nonce(mut self, nonce: Vec<u8> ) -> Self {
        self.nonce = nonce;
        self
    }
    pub fn set_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }
    pub fn set_timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }
    pub fn build(self, message: &str) -> Result<String, BrancaError> {
        let key = self.key;
        let nonce = self.nonce;
        let mut timestamp = self.timestamp;
        if timestamp <= 0 {
            // Generate a timestamp instead of a zero supplied one.
            let ts = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("Failed to obtain timestamp from system clock.");
            timestamp = ts.as_secs() as u32;
        }
        let crypted = encode(message, key, nonce, timestamp);
        return Ok(crypted.unwrap());
    }
}

pub fn encode(msg: &str, key: Vec<u8>, nonce: Vec<u8>, timestamp: u32) -> Result<String, BrancaError> {

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

    key_derv.copy_from_slice(key.as_slice());

    nonce_bytes.copy_from_slice(nonce.as_slice());

    let timestamp: u32 = timestamp;

    // The nonce is now appended to the timestamp in a vector.
    let mut time_bytes = vec![0x0; 4];

    BigEndian::write_u32(&mut time_bytes, timestamp);
    time_bytes.append(&mut Vec::from(nonce));

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

    let mut buf_crypt = Vec::with_capacity(msg.len());

    // Encrypt the payload with ChaCha20-Poly1305 AEAD (de-attached mode)
    // We return the tag to be used later to construct the rest of the branca token.

    // Use the version header as the authenticated additional data.
    let aead_tag = chacha20_poly1305_aead::encrypt(&part_crypted, &derv_nonce_2, &version_header, msg.as_bytes(), &mut buf_crypt).unwrap();

    // Append the tag to the ciphertext saved into the buffer.
    buf_crypt.append(&mut aead_tag.to_vec());

    // The ciphertext is appended to the version header.
    version_header.append(&mut buf_crypt);

    // Our payload is now encoded into base62. 
    let b62_enc = b62_encode(BASE62, &mut version_header.as_slice());
    
    // Return the branca token as a string.
    return Ok(b62_enc);
}

pub fn decode(data: &str, key: Vec<u8>, ttl: u32) -> Result<String, BrancaError> {

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
    
    key_bytes.copy_from_slice(key.as_slice());

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
    if &version.as_slice()[0] != &VERSION {
       return Err(BrancaError::InvalidTokenVersion);
    }

    let mut buf_crypt = Vec::with_capacity(ciphertext.len());

    // Retrieve the plaintext using ChaCha20-Poly1305 AEAD (de-attached mode)
    // We use the output of HChaCha20 (part_crypted) as the key with the
    // rest of the 16 byte nonce; i.e decrypting using XChaCha20 instead of ChaCha20.
    let decrypted = chacha20_poly1305_aead::decrypt(&part_crypted, &derv_nonce_2, &version_header, &ciphertext, &tag, &mut buf_crypt);

     if !decrypted.is_ok() {
         return Err(BrancaError::DecryptFailed);
     }

    // TTL check to determine if the token has expired.
     if ttl != 0 {
         let future = (timestamp + ttl) as u64;
         let time_now = SystemTime::now();
         let ts_seconds = time_now.duration_since(UNIX_EPOCH).expect("Failed to obtain timestamp from system clock.");
         let timestamp_now = ts_seconds.as_secs();
         if future < timestamp_now as u64 {
             return Err(BrancaError::ExpiredToken);
         }
    }

    // Return the plaintext.
    return Ok(String::from_utf8(buf_crypt).unwrap());
}