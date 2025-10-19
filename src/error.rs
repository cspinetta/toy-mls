//! Error types for the toy-mls implementation
//!
//! This module defines proper error types for the MLS implementation,
//! providing better error handling and debugging capabilities.

use std::fmt;

/// Main error type for MLS operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsError {
    /// Cryptographic operation failed
    CryptoError(String),

    /// Invalid tree operation
    TreeError(String),

    /// Invalid group operation
    GroupError(String),

    /// Invalid message or structure
    InvalidMessage(String),

    /// Signature verification failed
    SignatureError(String),

    /// Decryption failed
    DecryptionError(String),

    /// Invalid key or key package
    InvalidKey(String),

    /// Invalid leaf index
    InvalidLeafIndex(String),

    /// Invalid node index
    InvalidNodeIndex(String),

    /// Confirmation tag verification failed
    ConfirmationError(String),

    /// Generic error with message
    Other(String),
}

impl fmt::Display for MlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlsError::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            MlsError::TreeError(msg) => write!(f, "Tree error: {}", msg),
            MlsError::GroupError(msg) => write!(f, "Group error: {}", msg),
            MlsError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            MlsError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            MlsError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            MlsError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            MlsError::InvalidLeafIndex(msg) => write!(f, "Invalid leaf index: {}", msg),
            MlsError::InvalidNodeIndex(msg) => write!(f, "Invalid node index: {}", msg),
            MlsError::ConfirmationError(msg) => write!(f, "Confirmation error: {}", msg),
            MlsError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for MlsError {}

/// Result type for MLS operations
pub type MlsResult<T> = Result<T, MlsError>;

/// Convert from String to MlsError
impl From<String> for MlsError {
    fn from(s: String) -> Self {
        MlsError::Other(s)
    }
}

/// Convert from &str to MlsError
impl From<&str> for MlsError {
    fn from(s: &str) -> Self {
        MlsError::Other(s.to_string())
    }
}
