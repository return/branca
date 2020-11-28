use std::error::Error as StdErr;
use std::{fmt, result};

/// The type of Branca errors that can occur when encoding or decoding Branca tokens.
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Error {
    /// When the given input is not a valid Base62 encoding.
    InvalidBase62Token,
    /// When the version of the Branca token is mismatched.
    InvalidTokenVersion,
    /// When the nonce is of an incorrect size.
    BadNonceLength,
    /// When the key is of an incorrect size.
    BadKeyLength,
    /// When the token has exceeded its TTL.
    ExpiredToken,
    /// When the decryption of the ciphertext has failed.
    DecryptFailed,
    /// When encryption of the plaintext has failed.
    EncryptFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:?}", self)
    }
}

impl StdErr for Error {
    fn description(&self) -> &str {
        "branca error, see to_string() for details"
    }
}

/// Alias for `Result<T, Error>` used in the Branca module.
pub type Result<T> = result::Result<T, Error>;
