//! Error types for Zscan
//!
//! This module provides comprehensive error handling using `thiserror`
//! to distinguish between different failure modes during forensic collection.

use thiserror::Error;
use std::path::PathBuf;

/// Main error type for all forensics operations
#[derive(Error, Debug)]
pub enum ForensicsError {
    /// I/O errors during file operations (read-only enforcement failures)
    #[error("IO error accessing {path}: {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Permission denied when attempting to open file read-only
    #[error("Permission denied (read-only enforcement failed) for: {0}")]
    ReadOnlyViolation(PathBuf),

    /// Errors during parsing of binary artifacts
    #[error("Parse error in {artifact_type} at offset {offset}: {message}")]
    ParseError {
        artifact_type: String,
        offset: usize,
        message: String,
    },

    /// Errors during cryptographic hashing
    #[error("Hashing failed for {path}: {message}")]
    HashingError {
        path: PathBuf,
        message: String,
    },

    /// Invalid or unsupported file format
    #[error("Unsupported format: {path} - {reason}")]
    UnsupportedFormat {
        path: PathBuf,
        reason: String,
    },

    /// Path validation errors
    #[error("Invalid path: {path} - {reason}")]
    InvalidPath {
        path: PathBuf,
        reason: String,
    },

    /// Collector-specific errors
    #[error("Collector '{collector}' error: {message}")]
    CollectorError {
        collector: String,
        message: String,
    },

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type alias for forensics operations
pub type ForensicsResult<T> = Result<T, ForensicsError>;
