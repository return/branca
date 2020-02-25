# Branca - A secure alternative token format to JWT

|Crate|Documentation|License|Travis
|:---:|:-----------:|:-----------:|:-----------:|
|[![Crates.io][crates-badge]][crates-url]|[![Docs][doc-badge]][doc-url]|[![License][license-badge]][license-url]|[![Travis-CI][travis-badge]][travis-url]

[crates-badge]: https://img.shields.io/crates/v/branca.svg
[crates-url]: https://crates.io/crates/branca
[doc-badge]: https://docs.rs/branca/badge.svg
[doc-url]: https://docs.rs/branca
[license-badge]: https://img.shields.io/badge/License-MIT-brightgreen.svg
[license-url]: https://github.com/return/branca/blob/master/LICENSE
[travis-badge]: https://api.travis-ci.org/return/branca.svg?branch=master
[travis-url]: https://travis-ci.org/return/branca

Branca is a secure alternative token format to JWT. This implementation is written in pure Rust and uses the XChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) stream cipher for generating authenticated and encrypted tamper-proof tokens. More information about the branca token specification can be found here in [branca-spec.](https://github.com/tuupola/branca-spec/blob/master/README.md)

# Security

_NOTE: Branca uses orion for its cryptographic primitives and due to orion not recieving any formal security audit, the same security risks that orion has also applies to this Branca implementation if one uses it in production. For a better understanding about the security risks involved, see the orion [wiki](https://github.com/brycx/orion/wiki/Security)._

**⚠️ Use at your own risk. ⚠️**

# Requirements

* Rust 1.37
* Cargo

# Installation

Add this line into your Cargo.toml under the dependencies section:

```toml
[dependencies]
branca = "^0.9.0"
```

Then you can import the crate into your project with these lines:
```rust
extern crate branca;
use branca::{Branca, encode, decode};
```

# Example Usage

The simplest way to use this crate is to use `Branca::new()` in this example below:

```rust
    let key = b"supersecretkeyyoushouldnotcommit".to_vec();
    let token = Branca::new(&key).unwrap();
    let ciphertext = token.encode("Hello World!").unwrap();

    let payload = token.decode(ciphertext.as_str(), 0).unwrap();
    println("{}", payload); // "Hello World!"
```

See more examples of setting fields in the [Branca struct](https://docs.rs/branca/) and in the [Documentation section.](https://docs.rs/branca/0.8.0/branca/struct.Branca.html)

## Direct usage without Branca builder.
### Encoding:
```rust
let key = b"supersecretkeyyoushouldnotcommit".to_vec();

let message = "Hello world!";
let timestamp = 123206400;
let branca_token = encode(message,&key,timestamp).unwrap();

// branca_token = 875GH233T7.......
```

### Decoding:
```rust
let ciphertext = branca_token.as_str();
let key = b"supersecretkeyyoushouldnotcommit".to_vec();
let ttl = 0; // The ttl can be used to determine if the supplied token has expired or not.
let decoded = decode(ciphertext, &key, ttl);

if decoded.is_err() {
    // Error
} else {
    let msg = decoded.unwrap(); 
    // msg = "Hello world!"
}
```

## Encode/Decode arbitrary data structures with Serde.
Since Branca is able to work with any format of data in the payload, it is possible for the payload to be anything from a JSON object, plaintext, raw bytes, protocol buffers or even a JWT.

Here is a example of using Branca to encode/decode a typical JSON object with serde_json.

Add the following into your Cargo.toml file:
```toml
[dependencies]
branca = "^0.9.0"
serde_json = "^1.0"
serde_derive = "1.0.97"

```

```rust
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate branca;

use branca::{encode, decode};

#[derive(Serialize, Deserialize, Debug)]
struct User {
    user: String,
    scope: Vec<String>,
}

fn main(){

    let message = json!({
        "user" : "someone@example.com",
        "scope":["read", "write", "delete"],
    }).to_string();

    let key = b"supersecretkeyyoushouldnotcommit".to_vec();
    let token = Branca::new(&key).unwrap();
    
    // Encode Message
    let branca_token = token.encode(message.as_str()).unwrap();
    
    // Decode Message
    let payload = token.decode(branca_token.as_str(), 0).unwrap();

    let json: User = serde_json::from_str(payload.as_str()).unwrap();

    println!("{}", branca_token);
    println!("{}", payload);
    println!("{:?}", json);
}
```

Branca uses [Orion](https://github.com/brycx/orion) to generate secure random nonces when using the encode() and builder methods. By default, Branca does not allow setting the nonce directly since that there is a risk that it can be reused by the user which is a foot-gun.

The nonce generated **must be 24 bytes in length.** Keys **must be 32 bytes in length.**

# Building
`cargo build`

# Testing
`cargo test`

# Contributing
Contributions and patches are welcome! Fork this repository, add your changes and send a PR.

Before you send a PR, make sure you run `cargo test` first to check if your changes pass the tests.

If you would like to fix a bug or add a enhancement, please do so in the issues section and provide a short description about your changes.

# License
MIT