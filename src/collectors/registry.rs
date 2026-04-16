//! Registry Scanner Module
//!
//! Implements forensic collection of Windows Registry hives using
//! zero-copy parsing with the nom crate for memory efficiency.

use nom::bytes::complete::{tag, take};
use nom::number::complete::{le_u16, le_u32, le_u64};
use nom::IResult;
use std::path::PathBuf;
use anyhow::Result;
use async_trait::async_trait;
use walkdir::WalkDir;

use crate::{
    Collector,
    CollectionOptions,
    Artifact,
    ArtifactType,
    models::EvidenceMetadata,
};
use crate::utils::{open_readonly, compute_file_hash, read_file_header, filetime_to_datetime, detect_file_type};

/// Registry hive signature "regf"
const REGF_SIGNATURE: &[u8] = b"regf";

/// Registry file header structure (partial for forensic metadata extraction)
#[derive(Debug, Clone)]
pub struct RegistryHeader {
    pub signature: [u8; 4],
    pub sequence_number: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub root_cell_offset: u32,
    pub hive_bin_data_size: u32,
    pub clustering_factor: u32,
    pub last_written_timestamp: u64,
    pub checksum: u32,
}

/// Parses a Windows Registry hive header using nom
/// 
/// Header structure (first 512 bytes):
/// - Offset 0x00: Signature "regf" (4 bytes)
/// - Offset 0x04: Sequence number (4 bytes)
/// - Offset 0x08: Major version (4 bytes)
/// - Offset 0x0C: Minor version (4 bytes)
/// - Offset 0x10: File type (4 bytes)
/// - Offset 0x14: Root cell offset (4 bytes)
/// - Offset 0x18: Hive bin data size (4 bytes)
/// - Offset 0x1C: Clustering factor (4 bytes)
/// - Offset 0x20: Last written timestamp FILETIME (8 bytes)
/// - Offset 0x28: Checksum (4 bytes)
fn parse_registry_header(input: &[u8]) -> IResult<&[u8], RegistryHeader> {
    let (input, signature) = take(4usize)(input)?;
    let (input, sequence_number) = le_u32(input)?;
    let (input, major_version) = le_u32(input)?;
    let (input, minor_version) = le_u32(input)?;
    let (input, file_type) = le_u32(input)?;
    let (input, root_cell_offset) = le_u32(input)?;
    let (input, hive_bin_data_size) = le_u32(input)?;
    let (input, clustering_factor) = le_u32(input)?;
    let (input, last_written_timestamp) = le_u64(input)?;
    let (input, checksum) = le_u32(input)?;

    let mut sig_array = [0u8; 4];
    sig_array.copy_from_slice(signature);

    Ok((input, RegistryHeader {
        signature: sig_array,
        sequence_number,
        major_version,
        minor_version,
        file_type,
        root_cell_offset,
        hive_bin_data_size,
        clustering_factor,
        last_written_timestamp,
        checksum,
    }))
}

/// Determines the hive type from the filename
fn get_hive_type_from_filename(filename: &str) -> &'static str {
    match filename.to_lowercase().as_str() {
        "ntuser.dat" => "NTUSER.DAT (User hive)",
        "system" => "SYSTEM (System configuration)",
        "software" => "SOFTWARE (Installed software)",
        "security" => "SECURITY (Security policy)",
        "sam" => "SAM (User accounts)",
        "default" => "DEFAULT (Default user)",
        "usrclass.dat" => "UsrClass.DAT (COM/Shell settings)",
        "components" => "COMPONENTS (Windows components)",
        "drivers" => "DRIVERS (Driver settings)",
        _ => "Unknown Hive",
    }
}

/// Registry Scanner implementation
pub struct RegistryScanner;

impl RegistryScanner {
    /// Creates a new RegistryScanner instance
    pub fn new() -> Self {
        Self
    }

    /// Verifies if a file is a valid Windows Registry hive
    fn is_valid_registry_hive(&self, path: &PathBuf) -> bool {
        match read_file_header(path, 4) {
            Ok(header) => header == REGF_SIGNATURE,
            Err(_) => false,
        }
    }

    /// Extracts metadata from a registry hive file
    async fn extract_metadata(&self, path: &PathBuf) -> Result<EvidenceMetadata> {
        let header_data = read_file_header(path, 512)?;
        
        let header = match parse_registry_header(&header_data) {
            Ok((_, h)) => h,
            Err(_) => {
                // If parsing fails, return generic metadata
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                return Ok(EvidenceMetadata::Registry {
                    hive_type: get_hive_type_from_filename(filename).to_string(),
                    key_count: None,
                    value_count: None,
                    last_written: None,
                });
            }
        };

        // Convert FILETIME to DateTime
        let last_written = filetime_to_datetime(header.last_written_timestamp);

        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        Ok(EvidenceMetadata::Registry {
            hive_type: get_hive_type_from_filename(filename).to_string(),
            key_count: None, // Would require full hive parsing
            value_count: None,
            last_written,
        })
    }

    /// Scans a single file for registry artifacts
    async fn scan_file(
        &self,
        path: PathBuf,
        options: &CollectionOptions,
    ) -> Result<Option<Artifact>> {
        if !self.is_valid_registry_hive(&path) {
            return Ok(None);
        }

        // Get file metadata
        let metadata = tokio::fs::metadata(&path).await?;
        let file_size = metadata.len();

        // Check size limit
        if let Some(max_size) = options.max_file_size {
            if file_size > max_size {
                return Ok(None);
            }
        }

        // Compute hash if enabled
        let hash = if options.compute_hashes {
            Some(compute_file_hash(&path)?)
        } else {
            None
        };

        // Extract timestamps
        let modified_at = metadata.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::UNIX_EPOCH + chrono::Duration::try_from(d).ok()?);

        let created_at = metadata.created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::UNIX_EPOCH + chrono::Duration::try_from(d).ok()?);

        let accessed_at = metadata.accessed()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| chrono::DateTime::UNIX_EPOCH + chrono::Duration::try_from(d).ok()?);

        // Extract registry-specific metadata
        let evidence_metadata = self.extract_metadata(&path).await?;

        // Detect file type
        let (file_category, mime_type, file_type_desc) = detect_file_type(&path);

        // Generate unique ID
        let id = format!(
            "reg_{}",
            hash.as_ref()
                .map(|h| &h[..16])
                .unwrap_or_else(|| path.to_string_lossy().as_ref())
        );

        Ok(Some(Artifact {
            id,
            artifact_type: ArtifactType::RegistryHive,
            source_path: path,
            hash,
            file_size,
            created_at,
            modified_at,
            accessed_at,
            metadata: evidence_metadata,
            collector_name: self.name().to_string(),
        }))
    }
}

impl Default for RegistryScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for RegistryScanner {
    fn name(&self) -> &'static str {
        "registry_scanner"
    }

    fn artifact_types(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::RegistryHive]
    }

    async fn collect(&self, source: &PathBuf, options: &CollectionOptions) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();

        if source.is_file() {
            // Single file scan
            if let Some(artifact) = self.scan_file(source.clone(), options).await? {
                artifacts.push(artifact);
            }
        } else if source.is_dir() {
            // Directory scan using walkdir
            let walker = WalkDir::new(source)
                .follow_links(options.follow_symlinks)
                .max_depth(options.max_depth.unwrap_or(usize::MAX));

            for entry in walker {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }

                let path = entry.path().to_path_buf();
                
                if let Some(artifact) = self.scan_file(path, options).await? {
                    artifacts.push(artifact);
                }
            }
        }

        Ok(artifacts)
    }

    fn can_collect(&self, source: &PathBuf) -> bool {
        if source.is_file() {
            self.is_valid_registry_hive(source)
        } else if source.is_dir() {
            // Check if directory contains registry files
            WalkDir::new(source)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .any(|e| self.is_valid_registry_hive(&e.path().to_path_buf()))
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_registry_header() {
        // Test with mock registry header
        let mock_header = create_mock_registry_header();
        let result = parse_registry_header(&mock_header);
        assert!(result.is_ok());
        
        let (_, header) = result.unwrap();
        assert_eq!(&header.signature, b"regf");
        assert_eq!(header.major_version, 1);
    }

    fn create_mock_registry_header() -> Vec<u8> {
        let mut data = Vec::with_capacity(512);
        // Signature
        data.extend_from_slice(b"regf");
        // Sequence number
        data.extend_from_slice(&1u32.to_le_bytes());
        // Major version
        data.extend_from_slice(&1u32.to_le_bytes());
        // Minor version
        data.extend_from_slice(&3u32.to_le_bytes());
        // File type
        data.extend_from_slice(&0u32.to_le_bytes());
        // Root cell offset
        data.extend_from_slice(&0x20u32.to_le_bytes());
        // Hive bin data size
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        // Clustering factor
        data.extend_from_slice(&1u32.to_le_bytes());
        // Last written timestamp (FILETIME)
        data.extend_from_slice(&0u64.to_le_bytes());
        // Checksum
        data.extend_from_slice(&0u32.to_le_bytes());
        // Pad to 512 bytes
        data.resize(512, 0);
        data
    }
}
