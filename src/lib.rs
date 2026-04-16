//! Zscan
//! A high-performance Digital Forensics Triage Tool
//!
//! This library provides a modular, async-first framework for forensic
//! artifact collection with zero-copy parsing and read-only enforcement.

pub mod collectors;
pub mod error;
pub mod models;
pub mod orchestrator;
pub mod output;
pub mod utils;

use std::path::PathBuf;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use error::ForensicsError;
pub use models::{Artifact, ArtifactType, EvidenceMetadata};
pub use utils::{detect_file_type, FileTypeCategory};

/// Core trait that all artifact collectors must implement.
/// This defines the plugin interface for the modular system.
#[async_trait]
pub trait Collector: Send + Sync {
    /// Returns the unique name of this collector
    fn name(&self) -> &'static str;

    /// Returns the artifact types this collector can extract
    fn artifact_types(&self) -> Vec<ArtifactType>;

    /// Performs the collection operation on the specified source path
    /// 
    /// # Arguments
    /// * `source` - The path to scan for artifacts
    /// * `options` - Collection options including hashing and filtering
    ///
    /// # Returns
    /// A vector of discovered artifacts with metadata
    async fn collect(&self, source: &PathBuf, options: &CollectionOptions) -> Result<Vec<Artifact>>;

    /// Validates if this collector can handle the given source path
    ///
    /// # Arguments
    /// * `source` - The path to validate
    ///
    /// # Returns
    /// true if this collector can process the source, false otherwise
    fn can_collect(&self, source: &PathBuf) -> bool;
}

/// Options for controlling collection behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionOptions {
    /// Whether to calculate SHA-256 hashes for all files
    pub compute_hashes: bool,
    /// Maximum file size to process (in bytes)
    pub max_file_size: Option<u64>,
    /// File types to include (by magic bytes)
    pub file_type_filter: Option<Vec<String>>,
    /// Follow symbolic links during traversal
    pub follow_symlinks: bool,
    /// Maximum recursion depth for directory traversal
    pub max_depth: Option<usize>,
}

impl Default for CollectionOptions {
    fn default() -> Self {
        Self {
            compute_hashes: true,
            max_file_size: Some(100 * 1024 * 1024), // 100MB default
            file_type_filter: None,
            follow_symlinks: false,
            max_depth: None,
        }
    }
}

/// Configuration for the forensic triage operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageConfig {
    /// Source paths to scan
    pub sources: Vec<PathBuf>,
    /// Output directory for reports
    pub output_dir: PathBuf,
    /// Collection options
    pub options: CollectionOptions,
    /// List of collector names to enable (empty = all)
    pub enabled_collectors: Vec<String>,
}

/// Result of a triage operation
#[derive(Debug, Serialize, Deserialize)]
pub struct TriageResult {
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: chrono::DateTime<chrono::Utc>,
    pub artifacts_collected: usize,
    pub artifacts: Vec<Artifact>,
    pub errors: Vec<String>,
}
