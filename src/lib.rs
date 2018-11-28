extern crate sodiumoxide_xchacha20poly1305 as sodiumoxide;
extern crate byteorder;
extern crate base_x;
extern crate chrono;

pub mod errors;

use byteorder::*;
use base_x::{encode as b62_encode, decode as b62_decode};
use chrono::prelude::*;
use errors::Error as BrancaError;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as xchacha20;

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
    pub fn set_nonce(mut self, nonce:Vec<u8> ) -> Self {
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
    pub fn build(self, message: String) -> Result<String, BrancaError> {
        let key = self.key;
        let nonce = self.nonce;
        let mut timestamp = self.timestamp;
        if timestamp <= 0 {
            // Generate a timestamp instead of a zero supplied one.
            timestamp = Utc::now().timestamp() as u32;
        }
        let crypted = encode(message, key, nonce, timestamp);
        return Ok(crypted.unwrap());
    }
}

pub fn encode(msg: String, key: Vec<u8>, nonce: Vec<u8>, timestamp: u32) -> Result<String, BrancaError> {

    // Initialise sodiumoxide before doing anything else.
    sodiumoxide::init().map_err(|_e| BrancaError::SodiumInitFailed).ok();

    // Check the nonce length before going any further.
    if nonce.len() != 24 {
      return Err(BrancaError::BadNonceLength);
    }

    // Check the key length before going any further.
    if key.len() != 32 {
      return Err(BrancaError::BadKeyLength);
    }

    // We now can create a Key and Nonce struct from the inputs.
    let k = xchacha20::Key::from_slice(key.as_slice()).unwrap();

    let mut nonce_n = [0u8; NONCE_BYTES];
    nonce_n.copy_from_slice(nonce.as_slice());
    let nonce_b = xchacha20::Nonce(nonce_n);

    // The nonce is now appended to the timestamp in a Vector. 
    let mut time_bytes = vec![0x0; 4];
    BigEndian::write_u32(&mut time_bytes, timestamp);
    time_bytes.append(&mut Vec::from(nonce));

    // We append the version header to the timestamp vector.
    let mut version_header = vec![VERSION];
    version_header.append(&mut time_bytes);

    // Encrypt the payload using XChaCha20-Poly1305 AEAD //
    let mut crypted = xchacha20::seal(msg.as_bytes(), Some(version_header.as_slice()), &nonce_b, &k);

    // The ciphertext is appended to the version header
    version_header.append(&mut crypted);

    // Our payload is now encoded into base62. 
    let b62_enc = b62_encode(BASE62, &mut version_header.as_slice());
    
    // Return the branca token as a string.
    return Ok(b62_enc.to_string());
}

pub fn decode(data: String, key: Vec<u8>, ttl: u32) -> Result<String, BrancaError> {

    // The key must be 32 bytes in size.
    if key.len() != 32 {
        return Err(BrancaError::BadKeyLength);
    }

    let decoded_data = b62_decode(BASE62, &data).expect("Base62 token is invalid.");

    // Obtain supplied key
    let key = xchacha20::Key::from_slice(key.as_slice()).unwrap();

    // After we have decoded the data, the branca token is now represented
    // by the following layout below:

    // Branca( header[0..29] + ciphertext[29..] )
    // Version (&u8) || Timestamp (u32) || Nonce ([u8;24]) || Ciphertext (&[u8]) || Tag ([u8:16])
    // We then obtain the header, ciphertext, version and timestamp with this layout.
    let header = &decoded_data[0..29];
    let ciphertext = &decoded_data[29..];
    let version = &header[0];
    let timestamp = BigEndian::read_u32(&header[1..5]);

    // Obtain the nonce from the header // 
    let mut nonce_n = [0u8; NONCE_BYTES];
    nonce_n.copy_from_slice(&header[5..]);
    let nonce_b = xchacha20::Nonce(nonce_n);

    // Check the version 
    if version != &VERSION {
       return Err(BrancaError::InvalidTokenVersion);
    }

    // Retrieve plaintext using XChaCha20-Poly1305 AEAD
    let decrypted_plaintext = xchacha20::open(ciphertext, Some(header), &nonce_b, &key);

    if !decrypted_plaintext.is_ok() {
        return Err(BrancaError::DecryptFailed);
    }

    // Timestamp check for expried token //
    if ttl != 0 {
        let future = timestamp + ttl;
        let now = Utc::now().timestamp() as u32;
        if future < now {
            return Err(BrancaError::ExpiredToken);
        }
    }
    
    // Return the decoded string //
    return Ok(String::from_utf8(decrypted_plaintext.unwrap()).unwrap());
}