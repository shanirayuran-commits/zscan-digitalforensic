#!/usr/bin/env python3
"""
Zscan - Digital Forensics Triage Tool
Minimalistic Professional GUI
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QCheckBox, QComboBox,
    QSpinBox, QTextEdit, QProgressBar, QFileDialog, QTabWidget,
    QGroupBox, QScrollArea, QSplitter, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor


# Import core functionality from the CLI tool
from zscan import (
    ForensicOrchestrator, Artifact, format_bytes,
    generate_manifest, generate_markdown_report, generate_csv_report
)


class ScanWorker(QThread):
    """Worker thread for running forensic scans"""
    progress_update = pyqtSignal(str)
    artifact_found = pyqtSignal(dict)
    scan_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    progress_data = pyqtSignal(int, str, str)  # bytes_read, speed, eta

    def __init__(self, sources, options, enabled_collectors=None, concurrency=4):
        super().__init__()
        self.sources = sources
        self.options = options
        self.enabled_collectors = enabled_collectors
        self.concurrency = concurrency
        self.total_bytes = 0
        self.start_time = None

    def run(self):
        try:
            self.start_time = datetime.now()
            self.progress_update.emit("Initializing forensic orchestrator...")
            orchestrator = ForensicOrchestrator(
                concurrency=self.concurrency,
                enabled_collectors=self.enabled_collectors
            )

            self.progress_update.emit(f"Starting scan of {len(self.sources)} source(s)...")
            
            # Execute scan
            result = orchestrator.execute(self.sources, self.options)
            
            # Emit artifacts as they're found with progress (throttled)
            for idx, artifact in enumerate(result['artifacts']):
                self.artifact_found.emit(artifact.to_dict())
                self.total_bytes += artifact.file_size
                
                # Throttle progress updates - only update every 10 artifacts or every second
                if idx % 10 == 0 or idx == len(result['artifacts']) - 1:
                    # Calculate speed and ETA
                    elapsed = (datetime.now() - self.start_time).total_seconds()
                    if elapsed > 0:
                        speed = self.total_bytes / elapsed
                        eta = (self.total_bytes / speed) if speed > 0 else 0
                        self.progress_data.emit(self.total_bytes, format_bytes(speed), f"{eta:.1f}s")
                
                # Allow GUI to process events periodically
                if idx % 20 == 0:
                    self.msleep(10)  # Small sleep to prevent blocking
            
            self.progress_update.emit("Scan complete!")
            self.scan_complete.emit(result)
            
        except Exception as e:
            self.error_occurred.emit(str(e))


class ZscanGUI(QMainWindow):
    """Main GUI Application"""

    def __init__(self):
        super().__init__()
        self.scan_worker = None
        self.current_results = None
        self.output_dir = Path("./zscan-output")
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Zscan - Digital Forensics")
        self.setGeometry(100, 100, 1000, 700)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #ffffff;
            }
            QTabWidget::pane {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                background-color: #f9f9f9;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                color: #333333;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                color: #0078d4;
                border-bottom: 2px solid #0078d4;
            }
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:disabled {
                background-color: #d0d0d0;
                color: #808080;
            }
            QLineEdit {
                padding: 8px 12px;
                border: 1px solid #d0d0d0;
                border-radius: 6px;
                background-color: #ffffff;
                color: #333333;
            }
            QLineEdit:focus {
                border: 1px solid #0078d4;
            }
            QSpinBox {
                padding: 6px;
                border: 1px solid #d0d0d0;
                border-radius: 6px;
                background-color: #ffffff;
                color: #333333;
                selection-background-color: #0078d4;
                selection-color: white;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #f0f0f0;
                border: 1px solid #d0d0d0;
                border-radius: 3px;
                width: 20px;
            }
            QSpinBox::up-button:hover, QSpinBox::down-button:hover {
                background-color: #0078d4;
            }
            QSpinBox::up-arrow {
                image: none;
                border: none;
                background: none;
                width: 0;
                height: 0;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-bottom: 5px solid #333333;
                margin: 2px;
            }
            QSpinBox::down-arrow {
                image: none;
                border: none;
                background: none;
                width: 0;
                height: 0;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #333333;
                margin: 2px;
            }
            QCheckBox {
                color: #333333;
                spacing: 8px;
            }
            QLabel {
                color: #333333;
            }
            QGroupBox {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: 500;
                color: #333333;
                background-color: #f9f9f9;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
            }
            QTableWidget {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                gridline-color: #f0f0f0;
                background-color: #ffffff;
                color: #333333;
            }
            QTableWidget::item {
                padding: 8px;
                color: #333333;
            }
            QTableWidget::item:selected {
                background-color: #0078d4;
                color: white;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                color: #333333;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #e0e0e0;
                font-weight: 600;
            }
            QTextEdit {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                background-color: #ffffff;
                color: #333333;
                padding: 10px;
            }
            QProgressBar {
                border: 1px solid #e0e0e0;
                border-radius: 6px;
                text-align: center;
                background-color: #f0f0f0;
                color: #333333;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 4px;
            }
            QStatusBar {
                background-color: #f0f0f0;
                color: #333333;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(16)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        self.create_scan_tab()
        self.create_results_tab()
        self.create_reports_tab()
        
        self.statusBar().showMessage("Ready")


    def create_scan_tab(self):
        """Create the scan configuration tab"""
        scan_tab = QWidget()
        layout = QVBoxLayout(scan_tab)
        layout.setSpacing(12)
        
        # Source
        source_layout = QHBoxLayout()
        source_layout.addWidget(QLabel("Source:"))
        self.source_path_edit = QLineEdit()
        self.source_path_edit.setPlaceholderText("Select directory to scan")
        source_layout.addWidget(self.source_path_edit, 1)
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_source)
        source_layout.addWidget(browse_btn)
        layout.addLayout(source_layout)
        
        # Collectors - horizontal compact layout
        collector_layout = QHBoxLayout()
        collector_layout.addWidget(QLabel("Collectors:"))
        
        self.checkboxes = {}
        collectors = [
            ("registry_scanner", "Registry"),
            ("prefetch_scanner", "Prefetch"),
            ("event_log_scanner", "Event Logs"),
            ("lnk_scanner", "Shortcuts"),
            ("browser_history_scanner", "Browser"),
            ("generic_scanner", "All Files")
        ]
        
        for collector_id, name in collectors:
            checkbox = QCheckBox(name)
            checkbox.setChecked(True)
            self.checkboxes[collector_id] = checkbox
            collector_layout.addWidget(checkbox)
        
        collector_layout.addStretch()
        layout.addLayout(collector_layout)
        
        # Settings row
        settings_layout = QHBoxLayout()
        
        settings_layout.addWidget(QLabel("Max Size (MB):"))
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 10000)
        self.max_size_spin.setValue(1024)
        self.max_size_spin.setFixedWidth(100)
        settings_layout.addWidget(self.max_size_spin)
        
        settings_layout.addWidget(QLabel("Concurrency:"))
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 16)
        self.concurrency_spin.setValue(4)
        self.concurrency_spin.setFixedWidth(80)
        settings_layout.addWidget(self.concurrency_spin)
        
        self.hash_checkbox = QCheckBox("SHA-256")
        self.hash_checkbox.setChecked(True)
        settings_layout.addWidget(self.hash_checkbox)
        
        settings_layout.addStretch()
        layout.addLayout(settings_layout)
        
        # Output
        output_layout = QHBoxLayout()
        output_layout.addWidget(QLabel("Output:"))
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setText(str(self.output_dir))
        output_layout.addWidget(self.output_path_edit, 1)
        
        output_browse_btn = QPushButton("Browse")
        output_browse_btn.clicked.connect(self.browse_output)
        output_layout.addWidget(output_browse_btn)
        layout.addLayout(output_layout)
        
        # Scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setMinimumHeight(40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("background-color: #e74c3c;")
        self.stop_btn.clicked.connect(self.stop_scan)
        layout.addWidget(self.stop_btn)
        
        # Progress
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p% - Processing...")
        progress_layout.addWidget(self.progress_bar)
        
        # Progress info label
        self.progress_info = QLabel("")
        self.progress_info.setStyleSheet("color: #808080; font-size: 11px;")
        self.progress_info.setVisible(False)
        progress_layout.addWidget(self.progress_info)
        
        layout.addLayout(progress_layout)
        
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(120)
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text)
        
        layout.addStretch()
        self.tab_widget.addTab(scan_tab, "Scan")

    def create_results_tab(self):
        """Create the results display tab"""
        results_tab = QWidget()
        layout = QVBoxLayout(results_tab)
        layout.setSpacing(12)
        
        # Search and filter bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter results...")
        self.search_edit.textChanged.connect(self.filter_results)
        search_layout.addWidget(self.search_edit, 1)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by type:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Types")
        self.filter_combo.addItems(["Registry", "Prefetch", "Event Log", "Shortcut", "Browser"])
        self.filter_combo.currentTextChanged.connect(self.filter_results)
        filter_layout.addWidget(self.filter_combo)
        
        search_layout.addLayout(filter_layout)
        layout.addLayout(search_layout)
        
        # Export button
        export_btn = QPushButton("Export to Text File")
        export_btn.clicked.connect(self.export_to_text)
        layout.addWidget(export_btn)
        
        # Summary
        self.summary_label = QLabel("No scan results")
        self.summary_label.setStyleSheet("font-size: 14px; font-weight: 500; color: #808080; padding: 10px;")
        layout.addWidget(self.summary_label)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Type", "File Type", "Source", "Size", "SHA-256", "Collector"
        ])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        layout.addWidget(self.results_table)
        
        self.tab_widget.addTab(results_tab, "Results")
        self.all_artifacts = []  # Store all artifacts for filtering

    def create_reports_tab(self):
        """Create the reports tab"""
        reports_tab = QWidget()
        layout = QVBoxLayout(reports_tab)
        layout.setSpacing(12)
        
        # Report buttons
        button_layout = QHBoxLayout()
        
        self.view_json_btn = QPushButton("JSON")
        self.view_json_btn.clicked.connect(self.view_json_report)
        self.view_json_btn.setEnabled(False)
        button_layout.addWidget(self.view_json_btn)
        
        self.view_csv_btn = QPushButton("CSV")
        self.view_csv_btn.clicked.connect(self.view_csv_report)
        self.view_csv_btn.setEnabled(False)
        button_layout.addWidget(self.view_csv_btn)
        
        self.view_md_btn = QPushButton("Markdown")
        self.view_md_btn.clicked.connect(self.view_md_report)
        self.view_md_btn.setEnabled(False)
        button_layout.addWidget(self.view_md_btn)
        
        button_layout.addStretch()
        
        self.open_folder_btn = QPushButton("Open Folder")
        self.open_folder_btn.clicked.connect(self.open_output_folder)
        self.open_folder_btn.setEnabled(False)
        button_layout.addWidget(self.open_folder_btn)
        
        layout.addLayout(button_layout)
        
        # Report viewer
        self.report_viewer = QTextEdit()
        self.report_viewer.setReadOnly(True)
        self.report_viewer.setFont(QFont("Consolas", 9))
        layout.addWidget(self.report_viewer)
        
        self.tab_widget.addTab(reports_tab, "Reports")

    def browse_source(self):
        """Browse for source file or directory"""
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.Directory)
        if dialog.exec_():
            path = dialog.selectedFiles()[0]
            self.source_path_edit.setText(path)

    def browse_output(self):
        """Browse for output directory"""
        dialog = QFileDialog()
        dialog.setFileMode(QFileDialog.Directory)
        if dialog.exec_():
            path = dialog.selectedFiles()[0]
            self.output_path_edit.setText(path)
            self.output_dir = Path(path)

    def set_all_collectors(self, checked):
        """Set all collector checkboxes"""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(checked)

    def get_enabled_collectors(self):
        """Get list of enabled collectors"""
        return [name for name, checkbox in self.checkboxes.items() if checkbox.isChecked()]

    def start_scan(self):
        """Start the forensic scan"""
        source_path = self.source_path_edit.text()
        if not source_path:
            QMessageBox.warning(self, "Warning", "Please select a source path")
            return
        
        source = Path(source_path)
        if not source.exists():
            QMessageBox.warning(self, "Warning", "Source path does not exist")
            return
        
        # Get output directory
        self.output_dir = Path(self.output_path_edit.text())
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Build options
        self.options = {
            'compute_hashes': self.hash_checkbox.isChecked(),
            'max_file_size': self.max_size_spin.value() * 1024 * 1024,
            'max_depth': None,
            'follow_symlinks': False,
            'verbose': False
        }
        
        # Get enabled collectors
        enabled_collectors = self.get_enabled_collectors()
        if not enabled_collectors:
            QMessageBox.warning(self, "Warning", "Please select at least one collector")
            return
        
        # Update UI
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_info.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_text.clear()
        self.results_table.setRowCount(0)
        self.all_artifacts = []
        self.summary_label.setText("Scanning...")
        
        # Start worker thread
        self.scan_worker = ScanWorker(
            sources=[source],
            options=self.options,
            enabled_collectors=enabled_collectors,
            concurrency=self.concurrency_spin.value()
        )
        self.scan_worker.progress_update.connect(self.update_progress)
        self.scan_worker.artifact_found.connect(self.add_artifact_to_table)
        self.scan_worker.scan_complete.connect(self.scan_finished)
        self.scan_worker.error_occurred.connect(self.scan_error)
        self.scan_worker.progress_data.connect(self.update_progress_data)
        self.scan_worker.start()
        
        self.statusBar().showMessage("Scanning in progress...")

    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.terminate()
            self.scan_worker.wait()
            self.status_text.append("Scan stopped by user")
            self.reset_ui()

    def update_progress(self, message):
        """Update progress message"""
        self.status_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        self.status_text.verticalScrollBar().setValue(self.status_text.verticalScrollBar().maximum())
    
    def update_progress_data(self, bytes_read, speed, eta):
        """Update progress with data transfer info"""
        self.progress_info.setText(f"Data read: {format_bytes(bytes_read)} | Speed: {speed}/s | ETA: {eta}")
        # Update progress bar based on artifact count
        if self.all_artifacts:
            # Estimate total files based on bytes read and average file size
            avg_file_size = bytes_read / len(self.all_artifacts) if self.all_artifacts else 1024
            estimated_total = int(bytes_read / avg_file_size * 1.5) if avg_file_size > 0 else len(self.all_artifacts) * 2
            progress = min(100, int((len(self.all_artifacts) / max(estimated_total, len(self.all_artifacts))) * 100))
            self.progress_bar.setValue(progress)
            self.progress_bar.setFormat(f"%p% - {len(self.all_artifacts)} artifacts found")

    def add_artifact_to_table(self, artifact_dict):
        """Add artifact to results table"""
        self.all_artifacts.append(artifact_dict)
        self.filter_results()

    def scan_finished(self, result):
        """Handle scan completion"""
        self.current_results = result
        
        # Generate reports
        self.generate_reports(result)
        
        # Auto-save text report
        self.auto_save_text_report()
        
        # Update summary
        duration = int((result['end_time'] - result['start_time']).total_seconds())
        self.summary_label.setText(
            f"✅ Scan Complete! Found {result['artifacts_collected']} artifacts in {duration} seconds"
        )
        
        # Enable report buttons
        self.view_json_btn.setEnabled(True)
        self.view_csv_btn.setEnabled(True)
        self.view_md_btn.setEnabled(True)
        self.open_folder_btn.setEnabled(True)
        
        # Auto-display markdown report in Reports tab
        md_path = self.output_dir / "forensics_report.md"
        if md_path.exists():
            with open(md_path, 'r', encoding='utf-8') as f:
                self.report_viewer.setText(f.read())
        
        # Auto-switch to results tab
        self.tab_widget.setCurrentIndex(1)
        
        self.reset_ui()
        self.statusBar().showMessage(f"Scan complete - {result['artifacts_collected']} artifacts found")

    def scan_error(self, error_message):
        """Handle scan error"""
        self.status_text.append(f"❌ Error: {error_message}")
        QMessageBox.critical(self, "Error", f"Scan failed: {error_message}")
        self.reset_ui()

    def reset_ui(self):
        """Reset UI after scan"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.progress_info.setVisible(False)

    def generate_reports(self, result):
        """Generate all reports"""
        # JSON manifest
        manifest = generate_manifest(result)
        manifest_path = self.output_dir / "evidence_manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        # CSV report
        csv_path = self.output_dir / "evidence_report.csv"
        generate_csv_report(result, csv_path)
        
        # Markdown report
        report = generate_markdown_report(result)
        report_path = self.output_dir / "forensics_report.md"
        with open(report_path, 'w') as f:
            f.write(report)
        
        self.status_text.append(f"Reports saved to: {self.output_dir}")

    def view_json_report(self):
        """View JSON report"""
        manifest_path = self.output_dir / "evidence_manifest.json"
        if manifest_path.exists():
            with open(manifest_path, 'r') as f:
                content = json.dumps(json.load(f), indent=2)
                self.report_viewer.setText(content)
                self.tab_widget.setCurrentIndex(2)  # Switch to reports tab

    def view_csv_report(self):
        """View CSV report"""
        csv_path = self.output_dir / "evidence_report.csv"
        if csv_path.exists():
            with open(csv_path, 'r') as f:
                self.report_viewer.setText(f.read())
                self.tab_widget.setCurrentIndex(2)

    def view_md_report(self):
        """View Markdown report"""
        md_path = self.output_dir / "forensics_report.md"
        if md_path.exists():
            with open(md_path, 'r') as f:
                self.report_viewer.setText(f.read())
                self.tab_widget.setCurrentIndex(2)

    def filter_results(self):
        """Filter results based on search text and type"""
        search_text = self.search_edit.text().lower()
        filter_type = self.filter_combo.currentText()
        
        self.results_table.setRowCount(0)
        
        for artifact_dict in self.all_artifacts:
            # Check type filter
            if filter_type != "All Types":
                artifact_type = artifact_dict['artifact_type']
                if filter_type == "Registry" and "registry" not in artifact_type.lower():
                    continue
                elif filter_type == "Prefetch" and "prefetch" not in artifact_type.lower():
                    continue
                elif filter_type == "Event Log" and "event" not in artifact_type.lower():
                    continue
                elif filter_type == "Shortcut" and "lnk" not in artifact_type.lower():
                    continue
                elif filter_type == "Browser" and "browser" not in artifact_type.lower():
                    continue
            
            # Check search text
            source_name = str(Path(artifact_dict['source_path']).name).lower()
            if search_text and search_text not in source_name and search_text not in artifact_dict['artifact_type'].lower():
                continue
            
            # Add to table
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            
            self.results_table.setItem(row, 0, QTableWidgetItem(artifact_dict['artifact_type']))
            
            # Extract file type from metadata - handle both dict and JSON string
            file_type = "Unknown"
            metadata = artifact_dict.get('metadata', {})
            
            # If metadata is a string (JSON), parse it
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}
            
            # Get file type or file_category from metadata
            if isinstance(metadata, dict):
                file_type = metadata.get('file_type') or metadata.get('file_category') or 'Unknown'
            
            self.results_table.setItem(row, 1, QTableWidgetItem(str(file_type)))
            self.results_table.setItem(row, 2, QTableWidgetItem(str(Path(artifact_dict['source_path']).name)))
            self.results_table.setItem(row, 3, QTableWidgetItem(artifact_dict['file_size_human']))
            self.results_table.setItem(row, 4, QTableWidgetItem(artifact_dict['hash_sha256'][:12] + '...' if artifact_dict['hash_sha256'] else 'N/A'))
            self.results_table.setItem(row, 5, QTableWidgetItem(artifact_dict['collector']))
    
    def auto_save_text_report(self):
        """Auto-save text report to output folder"""
        if not self.all_artifacts:
            return
        
        try:
            text_path = self.output_dir / "results.txt"
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ZSCAN - FORENSIC SCAN RESULTS\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Total Artifacts: {len(self.all_artifacts)}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Group by type
                from collections import Counter
                type_counts = Counter(a['artifact_type'] for a in self.all_artifacts)
                f.write("Artifacts by Type:\n")
                for artifact_type, count in type_counts.most_common():
                    f.write(f"  - {artifact_type}: {count}\n")
                f.write("\n")
                
                f.write("-" * 80 + "\n")
                f.write("DETAILED FINDINGS\n")
                f.write("-" * 80 + "\n\n")
                
                for idx, artifact in enumerate(self.all_artifacts, 1):
                    f.write(f"[{idx}] {artifact['artifact_type'].upper()}\n")
                    f.write(f"    Source: {artifact['source_path']}\n")
                    f.write(f"    Size: {artifact['file_size_human']}\n")
                    f.write(f"    SHA-256: {artifact['hash_sha256'] or 'N/A'}\n")
                    f.write(f"    Collector: {artifact['collector']}\n")
                    if artifact.get('created_at'):
                        f.write(f"    Created: {artifact['created_at']}\n")
                    if artifact.get('modified_at'):
                        f.write(f"    Modified: {artifact['modified_at']}\n")
                    f.write("\n")
            
            self.statusBar().showMessage(f"Text report saved to {text_path}")
        except Exception as e:
            self.statusBar().showMessage(f"Failed to save text report: {e}")
    
    def export_to_text(self):
        """Export results to text file"""
        if not self.all_artifacts:
            QMessageBox.warning(self, "Warning", "No results to export")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", str(self.output_dir / "results.txt"), "Text Files (*.txt)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=" * 80 + "\n")
                    f.write("ZSCAN - FORENSIC SCAN RESULTS\n")
                    f.write("=" * 80 + "\n\n")
                    f.write(f"Total Artifacts: {len(self.all_artifacts)}\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    # Group by type
                    from collections import Counter
                    type_counts = Counter(a['artifact_type'] for a in self.all_artifacts)
                    f.write("Artifacts by Type:\n")
                    for artifact_type, count in type_counts.most_common():
                        f.write(f"  - {artifact_type}: {count}\n")
                    f.write("\n")
                    
                    f.write("-" * 80 + "\n")
                    f.write("DETAILED FINDINGS\n")
                    f.write("-" * 80 + "\n\n")
                    
                    for idx, artifact in enumerate(self.all_artifacts, 1):
                        f.write(f"[{idx}] {artifact['artifact_type'].upper()}\n")
                        f.write(f"    Source: {artifact['source_path']}\n")
                        f.write(f"    Size: {artifact['file_size_human']}\n")
                        f.write(f"    SHA-256: {artifact['hash_sha256'] or 'N/A'}\n")
                        f.write(f"    Collector: {artifact['collector']}\n")
                        if artifact.get('created_at'):
                            f.write(f"    Created: {artifact['created_at']}\n")
                        if artifact.get('modified_at'):
                            f.write(f"    Modified: {artifact['modified_at']}\n")
                        f.write("\n")
                
                QMessageBox.information(self, "Success", f"Results exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {e}")
    
    def open_output_folder(self):
        """Open output folder in file explorer"""
        if sys.platform == 'win32':
            subprocess.Popen(f'explorer "{self.output_dir}"')
        elif sys.platform == 'darwin':
            subprocess.Popen(['open', str(self.output_dir)])
        else:
            subprocess.Popen(['xdg-open', str(self.output_dir)])


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Set dark theme
    app.setPalette(app.style().standardPalette())
    
    window = ZscanGUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
