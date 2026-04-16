//! Output formatters
//!
//! Generates standardized forensic reports in JSON and Markdown formats

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use anyhow::Result;
use serde_json::Value;

use crate::{TriageResult, Artifact};
use crate::utils::format_bytes;

/// Evidence manifest structure for JSON export
#[derive(Debug, serde::Serialize)]
pub struct EvidenceManifest {
    pub case_info: CaseInfo,
    pub triage_summary: TriageSummary,
    pub artifacts: Vec<ArtifactEntry>,
}

#[derive(Debug, serde::Serialize)]
pub struct CaseInfo {
    pub tool_name: String,
    pub tool_version: String,
    pub generated_at: String,
    pub report_format: String,
}

#[derive(Debug, serde::Serialize)]
pub struct TriageSummary {
    pub start_time: String,
    pub end_time: String,
    pub total_artifacts: usize,
    pub total_errors: usize,
    pub duration_seconds: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct ArtifactEntry {
    pub id: String,
    pub artifact_type: String,
    pub source_path: String,
    pub hash_sha256: Option<String>,
    pub file_size_bytes: u64,
    pub file_size_human: String,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub accessed_at: Option<String>,
    pub collector: String,
    pub metadata: Value,
}

impl From<&Artifact> for ArtifactEntry {
    fn from(artifact: &Artifact) -> Self {
        Self {
            id: artifact.id.clone(),
            artifact_type: format!("{:?}", artifact.artifact_type),
            source_path: artifact.source_path.to_string_lossy().to_string(),
            hash_sha256: artifact.hash.clone(),
            file_size_bytes: artifact.file_size,
            file_size_human: format_bytes(artifact.file_size),
            created_at: artifact.created_at.map(|t| t.to_rfc3339()),
            modified_at: artifact.modified_at.map(|t| t.to_rfc3339()),
            accessed_at: artifact.accessed_at.map(|t| t.to_rfc3339()),
            collector: artifact.collector_name.clone(),
            metadata: serde_json::to_value(&artifact.metadata).unwrap_or(Value::Null),
        }
    }
}

/// Output formatter for generating forensic reports
pub struct ReportFormatter;

impl ReportFormatter {
    /// Creates a new report formatter
    pub fn new() -> Self {
        Self
    }

    /// Generates evidence_manifest.json
    pub fn generate_manifest(&self, result: &TriageResult) -> Result<EvidenceManifest> {
        let manifest = EvidenceManifest {
            case_info: CaseInfo {
                tool_name: "Zscan".to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                generated_at: chrono::Utc::now().to_rfc3339(),
                report_format: "evidence_manifest_v1".to_string(),
            },
            triage_summary: TriageSummary {
                start_time: result.start_time.to_rfc3339(),
                end_time: result.end_time.to_rfc3339(),
                total_artifacts: result.artifacts_collected,
                total_errors: result.errors.len(),
                duration_seconds: (result.end_time - result.start_time).num_seconds(),
            },
            artifacts: result.artifacts.iter().map(ArtifactEntry::from).collect(),
        };

        Ok(manifest)
    }

    /// Writes evidence manifest to JSON file
    pub fn write_manifest_json(&self, result: &TriageResult, output_path: &PathBuf) -> Result<()> {
        let manifest = self.generate_manifest(result)?;
        let json = serde_json::to_string_pretty(&manifest)?;
        
        let mut file = File::create(output_path)?;
        file.write_all(json.as_bytes())?;
        
        Ok(())
    }

    /// Generates markdown report
    pub fn generate_markdown_report(&self, result: &TriageResult) -> String {
        let mut report = String::new();
        
        // Header
        report.push_str("# Zscan Evidence Report\n\n");
        report.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now().to_rfc3339()));
        
        // Summary
        report.push_str("## Summary\n\n");
        report.push_str(&format!("- **Start Time:** {}\n", result.start_time.to_rfc3339()));
        report.push_str(&format!("- **End Time:** {}\n", result.end_time.to_rfc3339()));
        report.push_str(&format!("- **Duration:** {} seconds\n", 
            (result.end_time - result.start_time).num_seconds()));
        report.push_str(&format!("- **Total Artifacts:** {}\n", result.artifacts_collected));
        report.push_str(&format!("- **Errors:** {}\n\n", result.errors.len()));
        
        // Artifacts by type
        report.push_str("## Artifacts by Type\n\n");
        let mut type_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for artifact in &result.artifacts {
            let type_str = format!("{:?}", artifact.artifact_type);
            *type_counts.entry(type_str).or_insert(0) += 1;
        }
        
        for (artifact_type, count) in &type_counts {
            report.push_str(&format!("- **{}:** {}\n", artifact_type, count));
        }
        report.push('\n');
        
        // Detailed findings
        report.push_str("## Detailed Findings\n\n");
        
        for (idx, artifact) in result.artifacts.iter().enumerate() {
            report.push_str(&format!("### {}. {}\n\n", idx + 1, artifact.id));
            report.push_str(&format!("- **Type:** {:?}\n", artifact.artifact_type));
            report.push_str(&format!("- **Source:** `{}`\n", artifact.source_path.display()));
            report.push_str(&format!("- **Size:** {} ({} bytes)\n", 
                format_bytes(artifact.file_size), artifact.file_size));
            
            if let Some(ref hash) = artifact.hash {
                report.push_str(&format!("- **SHA-256:** `{}`\n", hash));
            }
            
            if let Some(ref created) = artifact.created_at {
                report.push_str(&format!("- **Created:** {}\n", created.to_rfc3339()));
            }
            
            if let Some(ref modified) = artifact.modified_at {
                report.push_str(&format!("- **Modified:** {}\n", modified.to_rfc3339()));
            }
            
            if let Some(ref accessed) = artifact.accessed_at {
                report.push_str(&format!("- **Accessed:** {}\n", accessed.to_rfc3339()));
            }
            
            report.push_str(&format!("- **Collector:** {}\n", artifact.collector_name));
            
            // Metadata
            match &artifact.metadata {
                crate::models::EvidenceMetadata::Registry { hive_type, last_written, .. } => {
                    report.push_str(&format!("- **Hive Type:** {}\n", hive_type));
                    if let Some(ts) = last_written {
                        report.push_str(&format!("- **Last Written:** {}\n", ts.to_rfc3339()));
                    }
                }
                crate::models::EvidenceMetadata::Prefetch { executable_name, run_count, .. } => {
                    report.push_str(&format!("- **Executable:** {}\n", executable_name));
                    report.push_str(&format!("- **Run Count:** {}\n", run_count));
                }
                _ => {}
            }
            
            report.push('\n');
        }
        
        // Errors
        if !result.errors.is_empty() {
            report.push_str("## Errors\n\n");
            for (idx, error) in result.errors.iter().enumerate() {
                report.push_str(&format!("{}. {}\n\n", idx + 1, error));
            }
        }
        
        // Footer
        report.push_str("---\n\n");
        report.push_str("*Generated by Zscan - Digital Forensics Triage Tool*\n");
        
        report
    }

    /// Writes markdown report to file
    pub fn write_markdown_report(&self, result: &TriageResult, output_path: &PathBuf) -> Result<()> {
        let report = self.generate_markdown_report(result);
        
        let mut file = File::create(output_path)?;
        file.write_all(report.as_bytes())?;
        
        Ok(())
    }

    /// Generates both JSON manifest and Markdown report
    pub fn generate_full_report(
        &self,
        result: &TriageResult,
        output_dir: &PathBuf,
    ) -> Result<(PathBuf, PathBuf)> {
        // Ensure output directory exists
        std::fs::create_dir_all(output_dir)?;
        
        // Generate manifest
        let manifest_path = output_dir.join("evidence_manifest.json");
        self.write_manifest_json(result, &manifest_path)?;
        
        // Generate markdown report
        let report_path = output_dir.join("forensics_report.md");
        self.write_markdown_report(result, &report_path)?;
        
        Ok((manifest_path, report_path))
    }
}

impl Default for ReportFormatter {
    fn default() -> Self {
        Self::new()
    }
}
