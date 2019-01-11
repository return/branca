use std::{fmt, result};
use std::error::Error as StdErr;

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
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.description())
    }
}

impl StdErr for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidBase62Token => "Base62 token is invalid.",
            Error::InvalidTokenVersion => "Token version is invalid.",
            Error::BadNonceLength => "Bad nonce length.",
            Error::BadKeyLength => "Bad key length.",
            Error::ExpiredToken => "This token has expired.",
            Error::DecryptFailed => "Decryption failed."
        }
    }
}

/// Alias for `Result<T, Error>` used in the Branca module.
pub type Result<T> = result::Result<T, Error>;