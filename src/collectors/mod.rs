//! Collectors module
//!
//! This module contains all artifact collector implementations.
//! Each collector implements the `Collector` trait and is registered
//! with the async orchestrator.

pub mod registry;

pub use registry::RegistryScanner;

use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;

use crate::{Collector, ArtifactType};

/// Registry of available collectors
pub struct CollectorRegistry {
    collectors: HashMap<String, Box<dyn Collector>>,
}

impl CollectorRegistry {
    /// Creates a new registry with all default collectors
    pub fn new() -> Self {
        let mut registry = Self {
            collectors: HashMap::new(),
        };
        
        // Register all built-in collectors
        registry.register(Box::new(registry::RegistryScanner::new()));
        
        registry
    }

    /// Registers a collector
    pub fn register(&mut self, collector: Box<dyn Collector>) {
        let name = collector.name().to_string();
        self.collectors.insert(name, collector);
    }

    /// Gets a collector by name
    pub fn get(&self, name: &str) -> Option<&dyn Collector> {
        self.collectors.get(name).map(|c| c.as_ref())
    }

    /// Returns all registered collectors
    pub fn all(&self) -> Vec<&dyn Collector> {
        self.collectors.values().map(|c| c.as_ref()).collect()
    }

    /// Finds collectors that can handle the given source path
    pub fn find_compatible(&self, source: &PathBuf) -> Vec<&dyn Collector> {
        self.collectors
            .values()
            .filter(|c| c.can_collect(source))
            .map(|c| c.as_ref())
            .collect()
    }

    /// Gets collectors by artifact type
    pub fn by_type(&self, artifact_type: &ArtifactType) -> Vec<&dyn Collector> {
        self.collectors
            .values()
            .filter(|c| {
                c.artifact_types()
                    .contains(artifact_type)
            })
            .map(|c| c.as_ref())
            .collect()
    }
}

impl Default for CollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}
