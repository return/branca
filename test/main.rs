extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

extern crate branca;
extern crate orion;

fn main() {}

#[cfg(test)]
mod branca_unit_tests {

    use branca::errors::Error as BrancaError;
    use branca::{decode, encode, Branca};
    use serde_json;

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
