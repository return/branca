use std::{fmt, result};
use std::error::Error as StdErr;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Error {
    InvalidBase62Token,
    InvalidTokenVersion,
    BadNonceLength,
    BadKeyLength,
    ExpiredToken,
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

pub type Result<T> = result::Result<T, Error>;