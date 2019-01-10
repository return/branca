extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

extern crate ring;
extern crate branca;

fn main(){}

 #[cfg(test)]
 mod branca_unit_tests {

     use branca::{Branca, encode, decode};
     use branca::errors::Error as BrancaError;
     use ring::rand::{SecureRandom, SystemRandom};
     use serde_json;

     #[derive(Serialize, Deserialize, Debug)]
     struct JSONTest {
         a: String,
         b: bool,
     }

     const NONCE_BYTES: [u8;24] = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

     #[test]
     pub fn test_encode() {
         let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
         let message = "Hello world!";
         let nonce = NONCE_BYTES.to_vec();
         let timestamp = 123206400;
         let branca_token = encode(message, &keygen, &nonce, timestamp).unwrap();

         assert_eq!(branca_token, "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
     }

      #[test]
      pub fn test_decode() {
          let ciphertext = "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
          let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
          let ttl = 0;

          assert_eq!(decode(ciphertext, &keygen, ttl).unwrap(), "Hello world!");
      }

     #[test]
     pub fn test_encode_and_decode() {
         let message = "Hello world!";
         let nonce = NONCE_BYTES.to_vec();
         let timestamp = 123206400;
         let branca_token = encode(message, &b"supersecretkeyyoushouldnotcommit".to_vec(), &nonce, timestamp).unwrap();

         assert_eq!(decode(branca_token.as_str(), &b"supersecretkeyyoushouldnotcommit".to_vec(), 0).unwrap(), "Hello world!");
     }

     #[test]
     pub fn test_encode_and_decode_random_nonce() {
         let message = "Hello world!";
         let rand_nonce  = SystemRandom::new();
         let mut buf_nonce = vec![0; 24];
         rand_nonce.fill(buf_nonce.as_mut()).unwrap();
         let timestamp = 123206400;
         let branca_token = encode(message, &b"supersecretkeyyoushouldnotcommit".to_vec(), &buf_nonce, timestamp).unwrap();

         assert_eq!(decode(branca_token.as_str(), &b"supersecretkeyyoushouldnotcommit".to_vec(), 0).unwrap(), "Hello world!");
     }

     #[test]
     pub fn test_encode_and_decode_json() {
         let literal_json = json!({ "a": "some string", "b": false });
         let message = literal_json.to_string();
         let nonce = NONCE_BYTES.to_vec();
         let timestamp = 123206400;
         let branca_token = encode(message.as_str(), &b"supersecretkeyyoushouldnotcommit".to_vec(), &nonce, timestamp).unwrap();
         let json = decode(branca_token.as_str(), &b"supersecretkeyyoushouldnotcommit".to_vec(), 0).unwrap();
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
         let nonce = NONCE_BYTES.to_vec();
         let timestamp = 123206400;
         let branca_token = encode(message, &b"supersecretkeyyoushouldnotcommit".to_vec(), &nonce, timestamp).unwrap();
         let json = decode(branca_token.as_str(), &b"supersecretkeyyoushouldnotcommit".to_vec(), 0).unwrap();
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
            Err(e) => { assert_eq!(e, BrancaError::ExpiredToken) },
            Ok(_) => { }
        }
    }

     #[test]
     pub fn test_encode_builder_get_and_set() {
         let mut token = Branca::new(&b"supersecretkeyyoushouldnotcommit".to_vec()).unwrap();
         let s = token.set_nonce(NONCE_BYTES.to_vec())
             .set_timestamp(123206400)
             .set_ttl(0)
             .encode("Hello world!");

         assert_eq!(s.unwrap(), "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
     }

      #[test]
      pub fn test_expired_ttl() {
          let ciphertext = "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
          let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
          let ttl = 3600;
          let message =  decode(ciphertext, &keygen, ttl);

          match message {
              Err(e) => { assert_eq!(e, BrancaError::ExpiredToken) },
              Ok(_) => {}
          }
     }

     #[test]
     pub fn test_decryption_fail() {
         let ciphertext = "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
         let keygen = b"supersecretkeyyoushouldnotcommi.".to_vec();
         let ttl = 0;
         let branca_token =  decode(ciphertext, &keygen, ttl);

         match branca_token {
             Err(e) => { assert_eq!(e, BrancaError::DecryptFailed) },
             Ok(_) => {}
         }
     }

     #[test]
     pub fn test_base62_fail() {
         let ciphertext = "875GH233T7IYrxtgXxlQBYiFo";
         let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
         let ttl = 0;
         let branca_token =  decode(ciphertext, &keygen, ttl);

         match branca_token {
             Err(e) => { assert_eq!(e, BrancaError::InvalidBase62Token) },
             Ok(_) => {}
         }
     }

     #[test]
     pub fn test_bad_nonce() {
         let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
         let message = "Hello world!";
         let nonce = Vec::from("\x01\x02\x03\x04\x05");
         let timestamp = 123206400;
         let branca_token = encode(message, &keygen, &nonce, timestamp);

         match branca_token {
             Err(e) => { assert_eq!(e, BrancaError::BadNonceLength) },
             Ok(_) => {}
         }
     }

     #[test]
     pub fn test_bad_key() {
         let keygen = b"supersecretkey".to_vec();
         let message = "Hello world!";
         let nonce = NONCE_BYTES.to_vec();
         let timestamp = 123206400;
         let branca_token = encode(message, &keygen, &nonce, timestamp);

         match branca_token {
             Err(e) => { assert_eq!(e, BrancaError::BadKeyLength) },
             Ok(_) => {}
         }
     }

     #[test]
     pub fn test_version_mismatch() {
         let ciphertext = "005GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a";
         let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
         let ttl = 0;
         let branca_token = decode(ciphertext, &keygen, ttl);

         match branca_token {
             Err(e) => { assert_eq!(e, BrancaError::InvalidTokenVersion) },
             Ok(_) => {}
         }
     }
 }
