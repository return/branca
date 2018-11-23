extern crate branca;

use branca::{Branca, encode, decode,};
 
fn main(){
}

#[cfg(test)]
mod branca_unit_tests {

    use super::*;
    use branca::{Branca, encode, decode};

    #[test]
    pub fn test_encode() {
        let keygen = String::from("supersecretkeyyoushouldnotcommit").into_bytes();
        let message = String::from("Hello world!");
        let nonce = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c].to_vec();
        let timestamp = 123206400;
        let branca_token = encode(message,keygen,nonce,timestamp).unwrap();
        assert_eq!(branca_token, "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
    }

    #[test]
    pub fn test_decode() {
        let ciphertext = String::from("875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
        let keygen = String::from("supersecretkeyyoushouldnotcommit");
        assert_eq!(decode(ciphertext, keygen).unwrap(), "Hello world!");
    }

   #[test]
    pub fn test_encode_builder() {
        let token = Branca::new()
        .set_key(String::from("supersecretkeyyoushouldnotcommit").into_bytes())
        .set_message(String::from("Hello world!"))
        .set_nonce([0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c].to_vec())
        .set_timestamp(123206400)
        .set_ttl(3600)
        .build();

        assert_eq!(token.unwrap(), "875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a");
    }
}
