#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate branca;
extern crate rand_chacha;
extern crate rand_core;

use branca::{encode, decode, Branca};

use rand_core::{RngCore, SeedableRng};


fuzz_target!(|data: &[u8]| {

    let mut csprng = rand_chacha::ChaCha20Rng::seed_from_u64(123456789u64);

    let mut key = vec![0u8; 32];
    csprng.try_fill_bytes(&mut key).unwrap();


    let mut ctx = Branca::new(&key).unwrap();

    if !ctx.decode(&String::from_utf8_lossy(data).to_string(), 0).is_err() {
        panic!("Decoded random string successfully");
    }
    if !decode(&String::from_utf8_lossy(data).to_string(), &key, 0).is_err() {
        panic!("Decoded random string successfully");
    }


    let valid_token_one = ctx.encode(data).unwrap();
    let valid_token_two = encode(data, &key, 0).unwrap();

    let payload_one = ctx.decode(&valid_token_two, 0);
    let payload_two = decode(&valid_token_one, &key, 0);
    
    match (payload_one, payload_two) {
        (Ok(p1), Ok(p2)) => assert_eq!(p1, p2),
        _ => panic!("Failed to decode valid token")
    };
});