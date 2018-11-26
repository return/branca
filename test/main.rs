extern crate branca;

fn main(){}

#[cfg(test)]
mod branca_unit_tests {

    use branca::{Branca, encode, decode};

    const NONCE_BYTES: [u8;24] = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c];

    #[test]
    pub fn test_encode() {
        let keygen = String::from("supersecretkeyyoushouldnotcommit").into_bytes();
        let message = String::from("Hello world!");
        let nonce = NONCE_BYTES.to_vec();
        let timestamp = 123206400;
        let branca_token = encode(message,keygen,nonce,timestamp).unwrap();
        assert_eq!(branca_token, "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
    }

    #[test]
    pub fn test_decode() {
        let ciphertext = String::from("875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
        let keygen = String::from("supersecretkeyyoushouldnotcommit");
        let ttl = 0;
        assert_eq!(decode(ciphertext, keygen, ttl).unwrap(), "Hello world!");
    }

   #[test]
    pub fn test_encode_builder() {
        let token = Branca::new()
        .set_key(String::from("supersecretkeyyoushouldnotcommit").into_bytes())
        .set_nonce(NONCE_BYTES.to_vec())
        .set_timestamp(123206400)
        .set_ttl(0)
        .build(String::from("Hello world!"));
        assert_eq!(token.unwrap(), "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
    }
}
