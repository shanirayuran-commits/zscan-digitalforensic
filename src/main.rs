//! Zscan CLI
//!
//! Command-line interface for the high-performance digital forensics triage tool.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use anyhow::Result;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::{
    ForensicOrchestrator,
    TriageConfig,
    CollectionOptions,
    output::ReportFormatter,
};

/// Zscan - High-Performance Digital Forensics Triage Tool
#[derive(Parser)]
#[command(name = "zscan")]
#[command(about = "High-performance digital forensics triage tool")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Source path(s) to scan for forensic artifacts
    #[arg(short, long, value_name = "PATH")]
    source: Vec<PathBuf>,

    /// Output directory for reports
    #[arg(short, long, value_name = "DIR", default_value = "./zscan-output")]
    output: PathBuf,

    /// Maximum file size to process (in MB)
    #[arg(long, value_name = "SIZE")]
    max_size: Option<u64>,

    /// Disable SHA-256 hashing for faster processing
    #[arg(long)]
    no_hash: bool,

    /// Maximum recursion depth for directory traversal
    #[arg(long, value_name = "DEPTH")]
    max_depth: Option<usize>,

    /// Follow symbolic links during traversal
    #[arg(long)]
    follow_links: bool,

    /// Concurrency limit for parallel operations
    #[arg(short, long, default_value = "4")]
    concurrency: usize,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Specific collector(s) to use (comma-separated)
    #[arg(long, value_name = "COLLECTORS")]
    collectors: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full triage scan
    Triage,
    
    /// List available collectors
    ListCollectors,
    
    /// Validate a source path for forensic collection
    Validate {
        /// Path to validate
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    
    /// Run a specific collector
    Collect {
        /// Collector name
        #[arg(value_name = "COLLECTOR")]
        collector: String,
        
        /// Source path
        #[arg(value_name = "SOURCE")]
        source: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Zscan v{} starting...", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Some(Commands::ListCollectors) | None if cli.source.is_empty() && std::env::args().len() == 1 => {
            list_collectors().await;
            return Ok(());
        }
        Some(Commands::ListCollectors) => {
            list_collectors().await;
            return Ok(());
        }
        Some(Commands::Validate { path }) => {
            validate_source(&path).await?;
            return Ok(());
        }
        Some(Commands::Collect { collector, source }) => {
            run_single_collector(&collector, &source, &cli).await?;
            return Ok(());
        }
        _ => {}
    }

    // Default: run triage
    if cli.source.is_empty() {
        eprintln!("Error: No source path specified. Use --source or run 'zscan list-collectors'");
        std::process::exit(1);
    }

    run_triage(cli).await?;

    Ok(())
}

async fn run_triage(cli: Cli) -> Result<()> {
    info!("Starting triage operation");
    info!("Sources: {:?}", cli.source);
    info!("Output: {}", cli.output.display());

    // Build collection options
    let mut options = CollectionOptions::default();
    options.compute_hashes = !cli.no_hash;
    options.follow_symlinks = cli.follow_links;
    options.max_depth = cli.max_depth;
    
    if let Some(max_size_mb) = cli.max_size {
        options.max_file_size = Some(max_size_mb * 1024 * 1024);
    }

    // Build config
    let config = TriageConfig {
        sources: cli.source,
        output_dir: cli.output.clone(),
        options,
        enabled_collectors: cli.collectors
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default(),
    };

    // Create orchestrator
    let orchestrator = ForensicOrchestrator::new()
        .with_concurrency(cli.concurrency);

    // Execute triage
    let result = orchestrator.execute(config).await?;

    // Generate reports
    let formatter = ReportFormatter::new();
    let (manifest_path, report_path) = formatter.generate_full_report(&result, &cli.output)?;

    info!("Triage complete!");
    info!("Artifacts collected: {}", result.artifacts_collected);
    info!("Evidence manifest: {}", manifest_path.display());
    info!("Report: {}", report_path.display());

    // Print summary to console
    println!("\n========================================");
    println!("  Zscan Triage Complete");
    println!("========================================");
    println!("Artifacts Found: {}", result.artifacts_collected);
    println!("Duration: {} seconds", (result.end_time - result.start_time).num_seconds());
    if !result.errors.is_empty() {
        println!("Errors: {}", result.errors.len());
    }
    println!("\nReports saved to: {}", cli.output.display());
    println!("  - {}", manifest_path.file_name().unwrap().to_string_lossy());
    println!("  - {}", report_path.file_name().unwrap().to_string_lossy());
    println!("========================================");

    Ok(())
}

async fn list_collectors() {
    let orchestrator = ForensicOrchestrator::new();
    let collectors = orchestrator.list_collectors();

    println!("\nAvailable Collectors:");
    println!("{:<20} {}", "Name", "Artifact Types");
    println!("{}", "-".repeat(60));

    for (name, types) in collectors {
        let type_names: Vec<String> = types.iter()
            .map(|t| format!("{:?}", t))
            .collect();
        println!("{:<20} {}", name, type_names.join(", "));
    }
    
    println!();
}

async fn validate_source(path: &PathBuf) -> Result<()> {
    use crate::collectors::CollectorRegistry;

    println!("\nValidating source: {}", path.display());

    if !path.exists() {
        eprintln!("Error: Path does not exist");
        std::process::exit(1);
    }

    let registry = CollectorRegistry::new();
    let compatible = registry.find_compatible(path);

    if compatible.is_empty() {
        println!("Status: No compatible collectors found");
        println!("This source may not contain supported forensic artifacts.");
    } else {
        println!("Status: Valid");
        println!("Compatible collectors:");
        for collector in compatible {
            println!("  - {}", collector.name());
        }
    }

    Ok(())
}

async fn run_single_collector(collector_name: &str, source: &PathBuf, cli: &Cli) -> Result<()> {
    info!("Running collector '{}' on {}", collector_name, source.display());

    let mut options = CollectionOptions::default();
    options.compute_hashes = !cli.no_hash;
    options.follow_symlinks = cli.follow_links;
    options.max_depth = cli.max_depth;

    if let Some(max_size_mb) = cli.max_size {
        options.max_file_size = Some(max_size_mb * 1024 * 1024);
    }

    let orchestrator = ForensicOrchestrator::new()
        .with_concurrency(cli.concurrency);

    match orchestrator.run_collector(collector_name, source, &options).await {
        Ok(artifacts) => {
            info!("Found {} artifacts", artifacts.len());
            
            // Create a minimal triage result for reporting
            let now = chrono::Utc::now();
            let result = crate::TriageResult {
                start_time: now,
                end_time: now,
                artifacts_collected: artifacts.len(),
                artifacts,
                errors: Vec::new(),
            };

            // Generate report
            let formatter = ReportFormatter::new();
            let (manifest_path, report_path) = formatter.generate_full_report(&result, &cli.output)?;

            println!("\nCollected {} artifacts", result.artifacts_collected);
            println!("Reports saved to: {}", cli.output.display());
            
            Ok(())
        }
        Err(e) => {
            error!("Collector failed: {}", e);
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
