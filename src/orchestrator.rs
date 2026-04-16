//! Async Orchestrator
//!
//! Manages concurrent artifact collection across multiple mount points
//! using tokio for non-blocking operations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::Result;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{info, warn, error};

use crate::{Collector, CollectionOptions, TriageConfig, TriageResult, Artifact};
use crate::collectors::CollectorRegistry;

/// Maximum concurrent collectors per source
const DEFAULT_CONCURRENCY_LIMIT: usize = 4;

/// Async orchestrator for managing forensic collection
pub struct ForensicOrchestrator {
    registry: Arc<CollectorRegistry>,
    concurrency_limit: usize,
}

impl ForensicOrchestrator {
    /// Creates a new orchestrator with default settings
    pub fn new() -> Self {
        Self {
            registry: Arc::new(CollectorRegistry::new()),
            concurrency_limit: DEFAULT_CONCURRENCY_LIMIT,
        }
    }

    /// Sets the concurrency limit for parallel operations
    pub fn with_concurrency(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit;
        self
    }

    /// Executes a full triage operation across all configured sources
    ///
    /// # Arguments
    /// * `config` - Triage configuration with sources and options
    ///
    /// # Returns
    /// Complete triage result with all artifacts
    pub async fn execute(&self, config: TriageConfig) -> Result<TriageResult> {
        let start_time = chrono::Utc::now();
        info!("Starting forensic triage operation");

        let mut all_artifacts: Vec<Artifact> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Create semaphore to limit concurrent operations
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));

        // Process each source concurrently
        let mut join_set = JoinSet::new();

        for source in &config.sources {
            let source = source.clone();
            let options = config.options.clone();
            let registry = self.registry.clone();
            let sem = semaphore.clone();

            join_set.spawn(async move {
                // Acquire semaphore permit
                let _permit = sem.acquire().await.map_err(|e| {
                    anyhow::anyhow!("Failed to acquire semaphore: {}", e)
                })?;

                Self::process_source(&source, &options, &registry).await
            });
        }

        // Collect results
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(Ok(artifacts)) => {
                    all_artifacts.extend(artifacts);
                }
                Ok(Err(e)) => {
                    warn!("Source processing error: {}", e);
                    errors.push(e.to_string());
                }
                Err(e) => {
                    error!("Task panicked: {}", e);
                    errors.push(format!("Task panicked: {}", e));
                }
            }
        }

        let end_time = chrono::Utc::now();
        
        // Dedupe artifacts by ID
        let unique_artifacts: Vec<Artifact> = {
            let mut seen = std::collections::HashSet::new();
            all_artifacts
                .into_iter()
                .filter(|a| seen.insert(a.id.clone()))
                .collect()
        };

        info!(
            "Triage completed: {} artifacts collected in {:?}",
            unique_artifacts.len(),
            end_time - start_time
        );

        Ok(TriageResult {
            start_time,
            end_time,
            artifacts_collected: unique_artifacts.len(),
            artifacts: unique_artifacts,
            errors,
        })
    }

    /// Processes a single source path
    async fn process_source(
        source: &PathBuf,
        options: &CollectionOptions,
        registry: &CollectorRegistry,
    ) -> Result<Vec<Artifact>> {
        info!("Processing source: {}", source.display());

        let mut artifacts = Vec::new();

        // Find compatible collectors
        let compatible = registry.find_compatible(source);
        
        if compatible.is_empty() {
            warn!("No compatible collectors found for: {}", source.display());
            return Ok(artifacts);
        }

        // Run each compatible collector
        for collector in compatible {
            match collector.collect(source, options).await {
                Ok(mut found) => {
                    info!(
                        "Collector '{}' found {} artifacts in {}",
                        collector.name(),
                        found.len(),
                        source.display()
                    );
                    artifacts.append(&mut found);
                }
                Err(e) => {
                    warn!(
                        "Collector '{}' failed on {}: {}",
                        collector.name(),
                        source.display(),
                        e
                    );
                }
            }
        }

        Ok(artifacts)
    }

    /// Runs a single collector against a source
    pub async fn run_collector(
        &self,
        collector_name: &str,
        source: &PathBuf,
        options: &CollectionOptions,
    ) -> Result<Vec<Artifact>> {
        let collector = self.registry
            .get(collector_name)
            .ok_or_else(|| anyhow::anyhow!("Collector not found: {}", collector_name))?;

        info!(
            "Running collector '{}' on {}",
            collector_name,
            source.display()
        );

        collector.collect(source, options).await
    }

    /// Lists all available collectors
    pub fn list_collectors(&self) -> Vec<(&'static str, Vec<ArtifactType>)> {
        self.registry
            .all()
            .into_iter()
            .map(|c| (c.name(), c.artifact_types()))
            .collect()
    }
}

impl Default for ForensicOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_orchestrator_creation() {
        let orchestrator = ForensicOrchestrator::new();
        let collectors = orchestrator.list_collectors();
        assert!(!collectors.is_empty());
        
        // Should have registry_scanner
        assert!(collectors.iter().any(|(name, _)| *name == "registry_scanner"));
    }
}
