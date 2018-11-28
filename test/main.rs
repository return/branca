extern crate branca;

fn main(){}

#[cfg(test)]
mod branca_unit_tests {

    use branca::{Branca, encode, decode};

    const NONCE_BYTES: [u8;24] = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

    #[test]
    pub fn test_encode() {
        let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
        let message = "Hello world!".to_string();
        let nonce = NONCE_BYTES.to_vec();
        let timestamp = 123206400;
        let branca_token = encode(message,keygen,nonce,timestamp).unwrap();
        assert_eq!(branca_token, "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
    }

    #[test]
    pub fn test_decode() {
        let ciphertext = "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a".to_string();
        let keygen = b"supersecretkeyyoushouldnotcommit".to_vec();
        let ttl = 0;
        assert_eq!(decode(ciphertext, keygen, ttl).unwrap(), "Hello world!");
    }

   #[test]
    pub fn test_encode_builder() {
        let token = Branca::new()
        .set_key(b"supersecretkeyyoushouldnotcommit".to_vec())
        .set_nonce(NONCE_BYTES.to_vec())
        .set_timestamp(123206400)
        .set_ttl(0)
        .build("Hello world!".to_string());
        assert_eq!(token.unwrap(), "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
    }
}
