//! Data models for forensic artifacts
//!
//! This module defines the core data structures used throughout
//! the forensic collection and reporting pipeline.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Types of forensic artifacts that can be collected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactType {
    /// Windows Registry hive
    RegistryHive,
    /// Windows Prefetch file
    Prefetch,
    /// Browser history (SQLite)
    BrowserHistory,
    /// Browser cache
    BrowserCache,
    /// System log file
    SystemLog,
    /// Application log file
    ApplicationLog,
    /// Event log (Windows EVTX)
    EventLog,
    /// SQLite database
    SqliteDatabase,
    /// File system metadata
    FileSystemMetadata,
    /// Jump list (Windows)
    JumpList,
    /// LNK file (Windows shortcut)
    LnkFile,
    /// Generic file
    GenericFile,
}

impl ArtifactType {
    /// Returns human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ArtifactType::RegistryHive => "Windows Registry Hive",
            ArtifactType::Prefetch => "Windows Prefetch File",
            ArtifactType::BrowserHistory => "Browser History Database",
            ArtifactType::BrowserCache => "Browser Cache",
            ArtifactType::SystemLog => "System Log",
            ArtifactType::ApplicationLog => "Application Log",
            ArtifactType::EventLog => "Windows Event Log (EVTX)",
            ArtifactType::SqliteDatabase => "SQLite Database",
            ArtifactType::FileSystemMetadata => "File System Metadata",
            ArtifactType::JumpList => "Windows Jump List",
            ArtifactType::LnkFile => "Windows Shortcut (LNK)",
            ArtifactType::GenericFile => "Generic File",
        }
    }
}

/// Represents a discovered forensic artifact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Unique identifier for this artifact
    pub id: String,
    /// Type of artifact
    pub artifact_type: ArtifactType,
    /// Original source path
    pub source_path: PathBuf,
    /// SHA-256 hash of the file (if computed)
    pub hash: Option<String>,
    /// File size in bytes
    pub file_size: u64,
    /// Creation timestamp (if available)
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Modification timestamp (if available)
    pub modified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Access timestamp (if available)
    pub accessed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Metadata specific to this artifact type
    pub metadata: EvidenceMetadata,
    /// Collector that discovered this artifact
    pub collector_name: String,
}

/// Type-specific metadata for artifacts
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EvidenceMetadata {
    /// Registry-specific metadata
    Registry {
        hive_type: String,
        key_count: Option<u64>,
        value_count: Option<u64>,
        last_written: Option<chrono::DateTime<chrono::Utc>>,
    },
    /// Prefetch-specific metadata
    Prefetch {
        executable_name: String,
        run_count: u32,
        last_run_time: Option<chrono::DateTime<chrono::Utc>>,
        volume_serial: Option<String>,
    },
    /// File system metadata
    FileSystem {
        inode: Option<u64>,
        permissions: Option<String>,
        owner: Option<String>,
        group: Option<String>,
    },
    /// Browser history metadata
    BrowserHistory {
        browser_name: String,
        entry_count: Option<u64>,
        profile_name: Option<String>,
    },
    /// Generic file metadata
    Generic {
        magic_bytes: Option<String>,
        mime_type: Option<String>,
        description: Option<String>,
        file_type: Option<String>,
        file_category: Option<String>,
    },
}

impl Default for EvidenceMetadata {
    fn default() -> Self {
        EvidenceMetadata::Generic {
            magic_bytes: None,
            mime_type: None,
            description: None,
            file_type: None,
            file_category: None,
        }
    }
}
