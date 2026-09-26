//! Unified fallible error type. Public APIs return [`Result`] instead of panicking.
use core::fmt;

/// Errors produced by this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Operation needs at least one leaf / element.
    EmptyInput,
    /// Index outside the committed domain.
    IndexOutOfBounds {
        /// Requested index.
        index: usize,
        /// Domain size.
        len: usize,
    },
    /// Domain size must be a power of two in the given range.
    InvalidDomainSize {
        /// Requested size.
        size: usize,
    },
    /// Blowup factor must be a power of two >= 1.
    InvalidBlowup {
        /// Requested factor.
        factor: usize,
    },
    /// FRI query count must be non-zero.
    NoQueries,
    /// A Merkle authentication path failed to verify.
    BadMerklePath,
    /// FRI folding relation or final polynomial check failed.
    FriVerificationFailed,
    /// Transcript or hash misuse.
    MalformedInput {
        /// Human-readable reason.
        reason: &'static str,
    },
    /// The operating-system RNG could not be read.
    RngUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input: need at least one element"),
            Self::IndexOutOfBounds { index, len } => {
                write!(f, "index {index} out of bounds (len {len})")
            }
            Self::InvalidDomainSize { size } => {
                write!(f, "invalid domain size {size}: must be a power of two")
            }
            Self::InvalidBlowup { factor } => {
                write!(f, "invalid blowup {factor}: must be a power-of-two >= 1")
            }
            Self::NoQueries => write!(f, "query count must be non-zero"),
            Self::BadMerklePath => write!(f, "merkle authentication path failed"),
            Self::FriVerificationFailed => write!(f, "FRI verification failed"),
            Self::MalformedInput { reason } => write!(f, "malformed input: {reason}"),
            Self::RngUnavailable => write!(f, "operating-system RNG unavailable"),
        }
    }
}

impl std::error::Error for Error {}

/// Crate-wide fallible result.
pub type Result<T> = core::result::Result<T, Error>;
