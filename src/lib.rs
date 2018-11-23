extern crate sodiumoxide;
extern crate serde;
extern crate byteorder;
extern crate chrono;
extern crate base_x;

use byteorder::*;
use chrono::prelude::*;
use base_x::*;

use sodiumoxide::randombytes::*;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf;
use std::io::*;
use std::io::Read;

// Branca magic byte
const VERSION: u8 = 0xBA;
// Branca nonce bytes
const NONCE_BYTES: usize = 24;
// Base 62 alphabet
const BASE62: &'static str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

// Branca builder
#[derive(Clone, PartialEq, Debug)]
pub struct Branca {
    key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    message:Option<String>,
    ttl: Option<u32>,
    timestamp: Option<u32>,
}

impl Branca {
    pub fn new () -> Branca {
        Branca {
            key: None,
            nonce: None,
            message: None,
            ttl: None,
            timestamp: None
        }
    }

    pub fn set_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }

    pub fn set_nonce(mut self, nonce:Vec<u8> ) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn set_message(mut self, message:String) -> Self {
        self.message = Some(message);
        self
    }

    pub fn set_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn set_timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    pub fn build(self) -> Result<String> {
        let key = self.key.unwrap();
        let nonce = self.nonce.unwrap();
        let message = self.message.unwrap();
        let ttl = self.ttl.unwrap();
        let timestamp = self.timestamp.unwrap();
        let crypted = encode(message, key, nonce, timestamp);
        return Ok(crypted.unwrap());
    }
}

pub fn encode(msg: String, key: Vec<u8>, nonce: Vec<u8>, timestamp: u32) -> Result<String> {

    sodiumoxide::init();

    let k = xchacha20poly1305_ietf::Key::from_slice(key.as_slice()).unwrap();

    let mut nonce_n: [u8; 24] = Default::default();
    nonce_n.copy_from_slice(nonce.as_slice());
    let nonce_b = xchacha20poly1305_ietf::Nonce(nonce_n);

    let timestamp: u32 = timestamp;

    let mut time_bytes = vec![0x0; 4];
    BigEndian::write_u32(&mut time_bytes, timestamp);
    time_bytes.append(&mut Vec::from(nonce));

    let mut version_header = vec![VERSION];
    version_header.append(&mut time_bytes);

    let mut crypted = xchacha20poly1305_ietf::seal(msg.as_bytes(), Some(version_header.as_slice()), &nonce_b, &k);

    version_header.append(&mut crypted);
    
    let b62_enc = base_x::encode(BASE62, &mut version_header.as_slice());
    
    return Ok(b62_enc.to_string());
}

pub fn decode(data: String, key: String) -> Result<String> {
    let g_data = base_x::decode(BASE62, &data).unwrap();
    let k = xchacha20poly1305_ietf::Key::from_slice(key.as_bytes()).unwrap();

    let header = &g_data[0..29];
    let ciphertext = &g_data[29..];

    let mut nonce_n: [u8; 24] = Default::default();
    nonce_n.copy_from_slice(&header[5..]);
    let nonce_b = xchacha20poly1305_ietf::Nonce(nonce_n);

    let decode = xchacha20poly1305_ietf::open(ciphertext, Some(header), &nonce_b, &k).unwrap();
    
    return Ok(String::from_utf8(decode).unwrap());
}