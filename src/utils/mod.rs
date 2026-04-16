//! Utility functions for Zscan
//!
//! Provides secure, read-only file operations and hashing utilities.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use anyhow::{Result, Context};
use sha2::{Sha256, Digest};
use crate::error::{ForensicsError, ForensicsResult};

/// Opens a file with strict read-only permissions for forensic integrity
///
/// # Arguments
/// * `path` - Path to the file to open
///
/// # Returns
/// A read-only file handle
pub fn open_readonly(path: &PathBuf) -> ForensicsResult<File> {
    // Use OpenOptions to enforce read-only access
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ForensicsError::ReadOnlyViolation(path.clone())
            } else {
                ForensicsError::IoError {
                    path: path.clone(),
                    source: e,
                }
            }
        })?;
    
    Ok(file)
}

/// Computes SHA-256 hash of a file using streaming to handle large files
///
/// # Arguments
/// * `path` - Path to the file to hash
///
/// # Returns
/// Hex-encoded SHA-256 hash string
pub fn compute_file_hash(path: &PathBuf) -> ForensicsResult<String> {
    const BUFFER_SIZE: usize = 8192;
    
    let mut file = open_readonly(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buffer[..n]);
            }
            Err(e) => {
                return Err(ForensicsError::HashingError {
                    path: path.clone(),
                    message: format!("Read error during hashing: {}", e),
                });
            }
        }
    }
    
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Reads a specific number of bytes from the start of a file
///
/// # Arguments
/// * `path` - Path to the file
/// * `count` - Number of bytes to read
///
/// # Returns
/// Vector of bytes read
pub fn read_file_header(path: &PathBuf, count: usize) -> ForensicsResult<Vec<u8>> {
    let mut file = open_readonly(path)?;
    let mut buffer = vec![0u8; count];
    
    let bytes_read = file.read(&mut buffer)
        .map_err(|e| ForensicsError::IoError {
            path: path.clone(),
            source: e,
        })?;
    
    buffer.truncate(bytes_read);
    Ok(buffer)
}

/// Safely resolves a path, handling UNC paths on Windows
///
/// # Arguments
/// * `path` - Input path
///
/// # Returns
/// Normalized PathBuf
pub fn normalize_path(path: &PathBuf) -> PathBuf {
    dunce::simplified(path).to_path_buf()
}

/// Format bytes as human-readable string
///
/// # Arguments
/// * `bytes` - Number of bytes
///
/// # Returns
/// Human-readable string like "1.5 MB"
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = bytes as f64 / 1024f64.powi(exp as i32);
    
    format!("{:.2} {}", value, UNITS[exp])
}

/// Converts a Windows FILETIME (100-nanosecond intervals since 1601-01-01)
/// to a chrono DateTime
///
/// # Arguments
/// * `filetime` - Windows FILETIME as u64
///
/// # Returns
/// UTC DateTime
pub fn filetime_to_datetime(filetime: u64) -> Option<chrono::DateTime<chrono::Utc>> {
    // FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
    // Difference is 11644473600 seconds
    const FILETIME_EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    
    if filetime < FILETIME_EPOCH_DIFF {
        return None;
    }
    
    let unix_nanos = filetime - FILETIME_EPOCH_DIFF;
    let seconds = (unix_nanos / 10_000_000) as i64;
    let nanos = ((unix_nanos % 10_000_000) * 100) as u32;
    
    chrono::DateTime::from_timestamp(seconds, nanos)
}

/// File type categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTypeCategory {
    Video,
    Audio,
    Image,
    Document,
    Spreadsheet,
    Archive,
    Executable,
    SystemFile,
    Database,
    Config,
    Log,
    Other,
}

impl FileTypeCategory {
    /// Returns human-readable name for the category
    pub fn name(&self) -> &'static str {
        match self {
            FileTypeCategory::Video => "Video",
            FileTypeCategory::Audio => "Audio",
            FileTypeCategory::Image => "Image",
            FileTypeCategory::Document => "Document",
            FileTypeCategory::Spreadsheet => "Spreadsheet",
            FileTypeCategory::Archive => "Archive",
            FileTypeCategory::Executable => "Executable",
            FileTypeCategory::SystemFile => "System File",
            FileTypeCategory::Database => "Database",
            FileTypeCategory::Config => "Configuration",
            FileTypeCategory::Log => "Log",
            FileTypeCategory::Other => "Other",
        }
    }
}

/// Detects file type from file extension
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// Tuple of (category, mime_type, file_type_description)
pub fn detect_file_type(path: &PathBuf) -> (FileTypeCategory, String, String) {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_lowercase();

    match extension.as_str() {
        // Video files
        "mp4" => (FileTypeCategory::Video, "video/mp4".to_string(), "MPEG-4 Video".to_string()),
        "mkv" => (FileTypeCategory::Video, "video/x-matroska".to_string(), "Matroska Video".to_string()),
        "avi" => (FileTypeCategory::Video, "video/x-msvideo".to_string(), "AVI Video".to_string()),
        "mov" => (FileTypeCategory::Video, "video/quicktime".to_string(), "QuickTime Video".to_string()),
        "wmv" => (FileTypeCategory::Video, "video/x-ms-wmv".to_string(), "Windows Media Video".to_string()),
        "flv" => (FileTypeCategory::Video, "video/x-flv".to_string(), "Flash Video".to_string()),
        "webm" => (FileTypeCategory::Video, "video/webm".to_string(), "WebM Video".to_string()),
        "m4v" => (FileTypeCategory::Video, "video/mp4".to_string(), "iTunes Video".to_string()),
        "mpg" | "mpeg" => (FileTypeCategory::Video, "video/mpeg".to_string(), "MPEG Video".to_string()),
        "ts" => (FileTypeCategory::Video, "video/mp2t".to_string(), "MPEG Transport Stream".to_string()),
        "vlc" => (FileTypeCategory::Video, "video/mp4".to_string(), "VLC Media File".to_string()),
        "mts" => (FileTypeCategory::Video, "video/mp2t".to_string(), "AVCHD Video".to_string()),
        "3gp" => (FileTypeCategory::Video, "video/3gpp".to_string(), "3GPP Video".to_string()),
        "ogv" => (FileTypeCategory::Video, "video/ogg".to_string(), "Ogg Video".to_string()),

        // Audio files
        "mp3" => (FileTypeCategory::Audio, "audio/mpeg".to_string(), "MP3 Audio".to_string()),
        "wav" => (FileTypeCategory::Audio, "audio/wav".to_string(), "WAV Audio".to_string()),
        "flac" => (FileTypeCategory::Audio, "audio/flac".to_string(), "FLAC Audio".to_string()),
        "aac" => (FileTypeCategory::Audio, "audio/aac".to_string(), "AAC Audio".to_string()),
        "ogg" => (FileTypeCategory::Audio, "audio/ogg".to_string(), "Ogg Audio".to_string()),
        "m4a" => (FileTypeCategory::Audio, "audio/mp4".to_string(), "iTunes Audio".to_string()),
        "wma" => (FileTypeCategory::Audio, "audio/x-ms-wma".to_string(), "Windows Media Audio".to_string()),
        "opus" => (FileTypeCategory::Audio, "audio/opus".to_string(), "Opus Audio".to_string()),

        // Image files
        "jpg" | "jpeg" => (FileTypeCategory::Image, "image/jpeg".to_string(), "JPEG Image".to_string()),
        "png" => (FileTypeCategory::Image, "image/png".to_string(), "PNG Image".to_string()),
        "gif" => (FileTypeCategory::Image, "image/gif".to_string(), "GIF Image".to_string()),
        "bmp" => (FileTypeCategory::Image, "image/bmp".to_string(), "Bitmap Image".to_string()),
        "tiff" | "tif" => (FileTypeCategory::Image, "image/tiff".to_string(), "TIFF Image".to_string()),
        "webp" => (FileTypeCategory::Image, "image/webp".to_string(), "WebP Image".to_string()),
        "svg" => (FileTypeCategory::Image, "image/svg+xml".to_string(), "SVG Image".to_string()),
        "ico" => (FileTypeCategory::Image, "image/x-icon".to_string(), "Icon File".to_string()),

        // Document files
        "pdf" => (FileTypeCategory::Document, "application/pdf".to_string(), "PDF Document".to_string()),
        "doc" => (FileTypeCategory::Document, "application/msword".to_string(), "Word Document".to_string()),
        "docx" => (FileTypeCategory::Document, "application/vnd.openxmlformats-officedocument.wordprocessingml.document".to_string(), "Word Document (XML)".to_string()),
        "txt" => (FileTypeCategory::Document, "text/plain".to_string(), "Plain Text".to_string()),
        "rtf" => (FileTypeCategory::Document, "application/rtf".to_string(), "Rich Text Format".to_string()),
        "odt" => (FileTypeCategory::Document, "application/vnd.oasis.opendocument.text".to_string(), "OpenDocument Text".to_string()),
        "md" => (FileTypeCategory::Document, "text/markdown".to_string(), "Markdown Document".to_string()),
        "html" | "htm" => (FileTypeCategory::Document, "text/html".to_string(), "HTML Document".to_string()),
        "xml" => (FileTypeCategory::Document, "application/xml".to_string(), "XML Document".to_string()),

        // Spreadsheet files
        "xls" => (FileTypeCategory::Spreadsheet, "application/vnd.ms-excel".to_string(), "Excel Spreadsheet".to_string()),
        "xlsx" => (FileTypeCategory::Spreadsheet, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_string(), "Excel Spreadsheet (XML)".to_string()),
        "csv" => (FileTypeCategory::Spreadsheet, "text/csv".to_string(), "CSV Spreadsheet".to_string()),
        "ods" => (FileTypeCategory::Spreadsheet, "application/vnd.oasis.opendocument.spreadsheet".to_string(), "OpenDocument Spreadsheet".to_string()),
        "tsv" => (FileTypeCategory::Spreadsheet, "text/tab-separated-values".to_string(), "Tab-Separated Values".to_string()),

        // Archive files
        "zip" => (FileTypeCategory::Archive, "application/zip".to_string(), "ZIP Archive".to_string()),
        "rar" => (FileTypeCategory::Archive, "application/x-rar-compressed".to_string(), "RAR Archive".to_string()),
        "7z" => (FileTypeCategory::Archive, "application/x-7z-compressed".to_string(), "7-Zip Archive".to_string()),
        "tar" => (FileTypeCategory::Archive, "application/x-tar".to_string(), "TAR Archive".to_string()),
        "gz" | "gzip" => (FileTypeCategory::Archive, "application/gzip".to_string(), "GZIP Archive".to_string()),
        "bz2" => (FileTypeCategory::Archive, "application/x-bzip2".to_string(), "Bzip2 Archive".to_string()),

        // Executable files
        "exe" => (FileTypeCategory::Executable, "application/x-msdownload".to_string(), "Windows Executable".to_string()),
        "dll" => (FileTypeCategory::Executable, "application/x-msdownload".to_string(), "Dynamic Link Library".to_string()),
        "sh" => (FileTypeCategory::Executable, "application/x-shellscript".to_string(), "Shell Script".to_string()),
        "bat" => (FileTypeCategory::Executable, "application/x-bat".to_string(), "Batch Script".to_string()),
        "cmd" => (FileTypeCategory::Executable, "application/x-cmd".to_string(), "Command Script".to_string()),
        "com" => (FileTypeCategory::Executable, "application/x-msdownload".to_string(), "DOS Executable".to_string()),

        // Database files
        "db" | "sqlite" => (FileTypeCategory::Database, "application/x-sqlite3".to_string(), "SQLite Database".to_string()),
        "mdb" => (FileTypeCategory::Database, "application/x-msaccess".to_string(), "Microsoft Access Database".to_string()),
        "accdb" => (FileTypeCategory::Database, "application/x-msaccess".to_string(), "Microsoft Access 2007+ Database".to_string()),
        "sql" => (FileTypeCategory::Database, "text/plain".to_string(), "SQL Script".to_string()),
        "dbf" => (FileTypeCategory::Database, "application/x-dbase".to_string(), "dBASE Database".to_string()),

        // Config/System files
        "ini" => (FileTypeCategory::Config, "text/plain".to_string(), "Configuration File".to_string()),
        "cfg" => (FileTypeCategory::Config, "text/plain".to_string(), "Configuration File".to_string()),
        "conf" => (FileTypeCategory::Config, "text/plain".to_string(), "Configuration File".to_string()),
        "json" => (FileTypeCategory::Config, "application/json".to_string(), "JSON Configuration".to_string()),
        "yaml" | "yml" => (FileTypeCategory::Config, "application/x-yaml".to_string(), "YAML Configuration".to_string()),
        "toml" => (FileTypeCategory::Config, "application/toml".to_string(), "TOML Configuration".to_string()),
        "plist" => (FileTypeCategory::Config, "application/x-plist".to_string(), "Property List".to_string()),
        "reg" => (FileTypeCategory::SystemFile, "text/plain".to_string(), "Windows Registry Export".to_string()),
        "sys" => (FileTypeCategory::SystemFile, "application/octet-stream".to_string(), "System File".to_string()),
        "dat" => (FileTypeCategory::SystemFile, "application/octet-stream".to_string(), "Data File".to_string()),

        // Log files
        "log" => (FileTypeCategory::Log, "text/plain".to_string(), "Log File".to_string()),
        "evtx" => (FileTypeCategory::Log, "application/x-evtx".to_string(), "Windows Event Log".to_string()),
        "evt" => (FileTypeCategory::Log, "application/x-evt".to_string(), "Windows Event Log (legacy)".to_string()),

        // Default
        _ => (FileTypeCategory::Other, format!("application/{}", extension), format!(".{} File", extension.to_uppercase())),
    }
}
