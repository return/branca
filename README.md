# branca

|Crate|Documentation|License|Travis
|:---:|:-----------:|:-----------:|:-----------:|
|[![Crates.io][crates-badge]][crates-url]|[![Docs][doc-badge]][doc-url]|![License][license-url]|![Travis-CI][travis-url]

[crates-badge]: https://img.shields.io/crates/v/branca.svg
[crates-url]: https://crates.io/crates/branca
[doc-badge]: https://docs.rs/branca/badge.svg
[doc-url]: https://docs.rs/branca
[license-badge]: https://img.shields.io/badge/License-MIT-brightgreen.svg
[license-url]: https://github.com/return/branca/blob/master/LICENSE
[travis-badge]: https://api.travis-ci.org/return/branca.svg?branch=master
[travis-url]: https://travis-ci.org/return/branca

Branca is a secure alternative token format to JWT. This implementation of the branca token specification is written in Rust and uses a fork of [sodiumoxide](https://github.com/return/sodiumoxide-xchacha20poly1305) for the XChaCha20-IETF-Poly1305 AEAD (Authenticated Encryption with Associated Data) stream cipher for generating encrypted tokens. More about the branca token specification can be found here in [branca-spec.](
https://github.com/tuupola/branca-spec/blob/master/README.md)

# Requirements

* Rust 1.18+
* Cargo

# Installation

Add this line to your Cargo.toml under the dependencies section:

```toml
[dependencies]
branca = "^0.1.1"
```

Then you can import the crate into your project with these lines:
```rust
extern crate branca
use branca::{Branca, encode, decode};
```

# Example Usage

## Encoding
```rust
let key = b"supersecretkeyyoushouldnotcommit".to_vec();
let nonce = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";

let message = "Hello world!".to_string();
let timestamp = 123206400;
let branca_token = encode(message,key,nonce,timestamp).unwrap();

// branca_token = 875GH233T7IYrxtgXxlQBYiFobZMQdHAT51vChKsAIYCFxZtL1evV54vYqLyZtQ0ekPHt8kJHQp0a
```

## Decoding
```rust
let ciphertext = branca_token.to_string();
let key = b"supersecretkeyyoushouldnotcommit".to_vec();
let ttl = 0; // The ttl can be used to determine if the supplied token has expired or not. //
let decoded = decode(ciphertext, key, ttl);

if decoded.is_err() {
    // Error
} else {
    let msg = decoded.unwrap(); 
    // msg = "Hello world!"
}
```
You can use either Ring's SecureRandom or sodiumoxide's aead gen_nonce() or gen_key() for generating secure nonces and keys for example. 

But do note that the nonce **must be 24 bytes in length.** Keys **must be 32 bytes in length.**

# Building
`cargo build`

# Testing
`cargo test --examples`

# License
MIT