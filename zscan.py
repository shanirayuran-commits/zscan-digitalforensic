#!/usr/bin/env python3
"""
Zscan - Python Edition v2.0
Digital Forensics Triage Tool with enhanced features
"""

import os
import sys
import json
import csv
import hashlib
import struct
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from collections import Counter


class ArtifactType:
    REGISTRY_HIVE = "registry_hive"
    PREFETCH = "prefetch"
    EVENT_LOG = "event_log"
    BROWSER_HISTORY = "browser_history"
    BROWSER_CACHE = "browser_cache"
    LNK_FILE = "lnk_file"
    JUMP_LIST = "jump_list"
    SYSTEM_LOG = "system_log"
    GENERIC_FILE = "generic_file"


class Artifact:
    def __init__(self, id: str, artifact_type: str, source_path: Path,
                 file_size: int, hash_val: Optional[str] = None,
                 created_at: Optional[datetime] = None,
                 modified_at: Optional[datetime] = None,
                 accessed_at: Optional[datetime] = None,
                 metadata: Optional[Dict] = None,
                 collector_name: str = ""):
        self.id = id
        self.artifact_type = artifact_type
        self.source_path = source_path
        self.file_size = file_size
        self.hash = hash_val
        self.created_at = created_at
        self.modified_at = modified_at
        self.accessed_at = accessed_at
        self.metadata = metadata or {}
        self.collector_name = collector_name

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "artifact_type": self.artifact_type,
            "source_path": str(self.source_path),
            "hash_sha256": self.hash,
            "file_size_bytes": self.file_size,
            "file_size_human": format_bytes(self.file_size),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "modified_at": self.modified_at.isoformat() if self.modified_at else None,
            "accessed_at": self.accessed_at.isoformat() if self.accessed_at else None,
            "collector": self.collector_name,
            "metadata": self.metadata
        }


def format_bytes(size: int) -> str:
    """Format bytes as human-readable string"""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = int(size)  # Convert to int to handle float values
    if size == 0:
        return "0 B"
    exp = min(int(size.bit_length() / 10), len(units) - 1)
    value = size / (1024 ** exp)
    return f"{value:.2f} {units[exp]}"


def compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def filetime_to_datetime(filetime: int) -> Optional[datetime]:
    """Convert Windows FILETIME to datetime"""
    # FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
    # Difference is 11644473600 seconds * 10^7 (100-nanosecond intervals)
    FILETIME_EPOCH_DIFF = 116444736000000000
    if filetime < FILETIME_EPOCH_DIFF:
        return None
    unix_nanos = filetime - FILETIME_EPOCH_DIFF
    seconds = unix_nanos // 10000000
    microseconds = (unix_nanos % 10000000) // 10
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=microseconds)


def detect_file_type(path: Path) -> Tuple[str, str, str]:
    """
    Detect file type from extension
    
    Returns: (category, mime_type, file_type_description)
    """
    ext = path.suffix.lower().lstrip('.')
    
    # Video files
    video_types = {
        'mp4': ('video/mp4', 'MPEG-4 Video'),
        'mkv': ('video/x-matroska', 'Matroska Video'),
        'avi': ('video/x-msvideo', 'AVI Video'),
        'mov': ('video/quicktime', 'QuickTime Video'),
        'wmv': ('video/x-ms-wmv', 'Windows Media Video'),
        'flv': ('video/x-flv', 'Flash Video'),
        'webm': ('video/webm', 'WebM Video'),
        'm4v': ('video/mp4', 'iTunes Video'),
        'mpg': ('video/mpeg', 'MPEG Video'),
        'mpeg': ('video/mpeg', 'MPEG Video'),
        'ts': ('video/mp2t', 'MPEG Transport Stream'),
        'vlc': ('video/mp4', 'VLC Media File'),
        'mts': ('video/mp2t', 'AVCHD Video'),
        '3gp': ('video/3gpp', '3GPP Video'),
        'ogv': ('video/ogg', 'Ogg Video'),
    }
    
    # Audio files
    audio_types = {
        'mp3': ('audio/mpeg', 'MP3 Audio'),
        'wav': ('audio/wav', 'WAV Audio'),
        'flac': ('audio/flac', 'FLAC Audio'),
        'aac': ('audio/aac', 'AAC Audio'),
        'ogg': ('audio/ogg', 'Ogg Audio'),
        'm4a': ('audio/mp4', 'iTunes Audio'),
        'wma': ('audio/x-ms-wma', 'Windows Media Audio'),
        'opus': ('audio/opus', 'Opus Audio'),
    }
    
    # Image files
    image_types = {
        'jpg': ('image/jpeg', 'JPEG Image'),
        'jpeg': ('image/jpeg', 'JPEG Image'),
        'png': ('image/png', 'PNG Image'),
        'gif': ('image/gif', 'GIF Image'),
        'bmp': ('image/bmp', 'Bitmap Image'),
        'tiff': ('image/tiff', 'TIFF Image'),
        'tif': ('image/tiff', 'TIFF Image'),
        'webp': ('image/webp', 'WebP Image'),
        'svg': ('image/svg+xml', 'SVG Image'),
        'ico': ('image/x-icon', 'Icon File'),
    }
    
    # Document files
    document_types = {
        'pdf': ('application/pdf', 'PDF Document'),
        'doc': ('application/msword', 'Word Document'),
        'docx': ('application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'Word Document (XML)'),
        'txt': ('text/plain', 'Plain Text'),
        'rtf': ('application/rtf', 'Rich Text Format'),
        'odt': ('application/vnd.oasis.opendocument.text', 'OpenDocument Text'),
        'md': ('text/markdown', 'Markdown Document'),
        'html': ('text/html', 'HTML Document'),
        'htm': ('text/html', 'HTML Document'),
        'xml': ('application/xml', 'XML Document'),
    }
    
    # Spreadsheet files
    spreadsheet_types = {
        'xls': ('application/vnd.ms-excel', 'Excel Spreadsheet'),
        'xlsx': ('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Excel Spreadsheet (XML)'),
        'csv': ('text/csv', 'CSV Spreadsheet'),
        'ods': ('application/vnd.oasis.opendocument.spreadsheet', 'OpenDocument Spreadsheet'),
        'tsv': ('text/tab-separated-values', 'Tab-Separated Values'),
    }
    
    # Archive files
    archive_types = {
        'zip': ('application/zip', 'ZIP Archive'),
        'rar': ('application/x-rar-compressed', 'RAR Archive'),
        '7z': ('application/x-7z-compressed', '7-Zip Archive'),
        'tar': ('application/x-tar', 'TAR Archive'),
        'gz': ('application/gzip', 'GZIP Archive'),
        'gzip': ('application/gzip', 'GZIP Archive'),
        'bz2': ('application/x-bzip2', 'Bzip2 Archive'),
    }
    
    # Executable/Script files
    executable_types = {
        'exe': ('application/x-msdownload', 'Windows Executable'),
        'dll': ('application/x-msdownload', 'Dynamic Link Library'),
        'sh': ('application/x-shellscript', 'Shell Script'),
        'bat': ('application/x-bat', 'Batch Script'),
        'cmd': ('application/x-cmd', 'Command Script'),
        'com': ('application/x-msdownload', 'DOS Executable'),
    }
    
    # Database files
    database_types = {
        'db': ('application/x-sqlite3', 'SQLite Database'),
        'sqlite': ('application/x-sqlite3', 'SQLite Database'),
        'mdb': ('application/x-msaccess', 'Microsoft Access Database'),
        'accdb': ('application/x-msaccess', 'Microsoft Access 2007+ Database'),
        'sql': ('text/plain', 'SQL Script'),
        'dbf': ('application/x-dbase', 'dBASE Database'),
    }
    
    # Config/System files
    config_types = {
        'ini': ('text/plain', 'Configuration File'),
        'cfg': ('text/plain', 'Configuration File'),
        'conf': ('text/plain', 'Configuration File'),
        'json': ('application/json', 'JSON Configuration'),
        'yaml': ('application/x-yaml', 'YAML Configuration'),
        'yml': ('application/x-yaml', 'YAML Configuration'),
        'toml': ('application/toml', 'TOML Configuration'),
        'plist': ('application/x-plist', 'Property List'),
        'reg': ('text/plain', 'Windows Registry Export'),
        'sys': ('application/octet-stream', 'System File'),
        'dat': ('application/octet-stream', 'Data File'),
    }
    
    # Log files
    log_types = {
        'log': ('text/plain', 'Log File'),
        'evtx': ('application/x-evtx', 'Windows Event Log'),
        'evt': ('application/x-evt', 'Windows Event Log (legacy)'),
    }
    
    # Check file type
    all_types = {
        'Video': video_types,
        'Audio': audio_types,
        'Image': image_types,
        'Document': document_types,
        'Spreadsheet': spreadsheet_types,
        'Archive': archive_types,
        'Executable': executable_types,
        'Database': database_types,
        'Config': config_types,
        'Log': log_types,
    }
    
    for category, type_dict in all_types.items():
        if ext in type_dict:
            mime, desc = type_dict[ext]
            return (category, mime, desc)
    
    # Default
    return ('Other', f'application/{ext}', f'.{ext.upper()} File')


def parse_registry_header(data: bytes) -> Optional[Dict]:
    """Parse Windows Registry hive header"""
    if len(data) < 512:
        return None
    
    # Check signature
    if data[:4] != b'regf':
        return None
    
    try:
        # Unpack header structure
        sequence_number = struct.unpack('<I', data[4:8])[0]
        major_version = struct.unpack('<I', data[8:12])[0]
        minor_version = struct.unpack('<I', data[12:16])[0]
        file_type = struct.unpack('<I', data[16:20])[0]
        root_cell_offset = struct.unpack('<I', data[20:24])[0]
        hive_bin_data_size = struct.unpack('<I', data[24:28])[0]
        clustering_factor = struct.unpack('<I', data[28:32])[0]
        last_written_timestamp = struct.unpack('<Q', data[32:40])[0]
        checksum = struct.unpack('<I', data[40:44])[0]
        
        return {
            "sequence_number": sequence_number,
            "major_version": major_version,
            "minor_version": minor_version,
            "file_type": file_type,
            "root_cell_offset": root_cell_offset,
            "hive_bin_data_size": hive_bin_data_size,
            "clustering_factor": clustering_factor,
            "last_written": filetime_to_datetime(last_written_timestamp),
            "checksum": checksum
        }
    except struct.error:
        return None


def get_hive_type_from_filename(filename: str) -> str:
    """Determine hive type from filename"""
    name_lower = filename.lower()
    hive_types = {
        "ntuser.dat": "NTUSER.DAT (User hive)",
        "system": "SYSTEM (System configuration)",
        "software": "SOFTWARE (Installed software)",
        "security": "SECURITY (Security policy)",
        "sam": "SAM (User accounts)",
        "default": "DEFAULT (Default user)",
        "usrclass.dat": "UsrClass.DAT (COM/Shell settings)",
        "components": "COMPONENTS (Windows components)",
        "drivers": "DRIVERS (Driver settings)",
    }
    return hive_types.get(name_lower, "Unknown Hive")


def is_registry_hive(path: Path) -> bool:
    """Check if file is a valid Windows Registry hive"""
    try:
        with open(path, 'rb') as f:
            header = f.read(4)
            return header == b'regf'
    except:
        return False


class RegistryScanner:
    """Scanner for Windows Registry hives"""
    
    def __init__(self):
        self.name = "registry_scanner"
    
    def can_collect(self, source: Path) -> bool:
        """Check if this collector can handle the source"""
        if source.is_file():
            return is_registry_hive(source)
        elif source.is_dir():
            # Check if directory contains registry files
            for item in source.rglob("*"):
                if item.is_file() and is_registry_hive(item):
                    return True
            return False
        return False
    
    def collect(self, source: Path, options: Dict) -> List[Artifact]:
        """Collect registry artifacts from source"""
        artifacts = []
        max_size = options.get('max_file_size', 100 * 1024 * 1024)
        compute_hashes = options.get('compute_hashes', True)
        max_depth = options.get('max_depth')
        
        files_to_scan = []
        
        if source.is_file():
            files_to_scan.append(source)
        elif source.is_dir():
            # Walk directory
            for root, dirs, files in os.walk(source):
                current_depth = len(Path(root).relative_to(source).parts)
                if max_depth and current_depth > max_depth:
                    dirs[:] = []  # Stop descending
                    continue
                
                for filename in files:
                    file_path = Path(root) / filename
                    files_to_scan.append(file_path)
        
        # Scan files
        for file_path in files_to_scan:
            if not is_registry_hive(file_path):
                continue
            
            try:
                stat = file_path.stat()
                
                # Check size limit
                if stat.st_size > max_size:
                    continue
                
                # Compute hash
                hash_val = None
                if compute_hashes:
                    hash_val = compute_file_hash(file_path)
                
                # Parse registry header
                with open(file_path, 'rb') as f:
                    header_data = f.read(512)
                
                header_info = parse_registry_header(header_data)
                
                # Create artifact
                filename = file_path.name
                metadata = {
                    "hive_type": get_hive_type_from_filename(filename),
                    "key_count": None,
                    "value_count": None,
                    "last_written": header_info['last_written'].isoformat() if header_info and header_info['last_written'] else None,
                    "header": header_info
                }
                
                # Timestamps
                created_at = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc) if hasattr(stat, 'st_ctime') else None
                modified_at = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                accessed_at = datetime.fromtimestamp(stat.st_atime, tz=timezone.utc) if hasattr(stat, 'st_atime') else None
                
                # Generate ID
                artifact_id = f"reg_{hash_val[:16] if hash_val else filename}"
                
                artifact = Artifact(
                    id=artifact_id,
                    artifact_type=ArtifactType.REGISTRY_HIVE,
                    source_path=file_path,
                    file_size=stat.st_size,
                    hash_val=hash_val,
                    created_at=created_at,
                    modified_at=modified_at,
                    accessed_at=accessed_at,
                    metadata=metadata,
                    collector_name=self.name
                )
                
                artifacts.append(artifact)
                print(f"  Found: {filename} ({format_bytes(stat.st_size)})")
                
            except Exception as e:
                print(f"  Error scanning {file_path}: {e}")
                continue
        
        return artifacts


class PrefetchScanner:
    """Scanner for Windows Prefetch files"""
    
    def __init__(self):
        self.name = "prefetch_scanner"
    
    def can_collect(self, source: Path) -> bool:
        if source.is_file():
            return self._is_prefetch_file(source)
        elif source.is_dir():
            for item in source.rglob("*.pf"):
                if self._is_prefetch_file(item):
                    return True
            return False
        return False
    
    def _is_prefetch_file(self, path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                # Check SCCA signature at offset 4
                f.seek(4)
                sig = f.read(4)
                return sig in [b'SCCA', b'SCC\xa0', b'SCC\x80']
        except:
            return False
    
    def collect(self, source: Path, options: Dict) -> List[Artifact]:
        artifacts = []
        max_size = options.get('max_file_size', 100 * 1024 * 1024)
        compute_hashes = options.get('compute_hashes', True)
        max_depth = options.get('max_depth')
        
        files_to_scan = []
        
        if source.is_file():
            files_to_scan.append(source)
        elif source.is_dir():
            pattern = source.rglob("*.pf") if max_depth is None else source.glob("**/*.pf")
            for file_path in pattern:
                if self._is_prefetch_file(file_path):
                    files_to_scan.append(file_path)
        
        for file_path in files_to_scan:
            try:
                stat = file_path.stat()
                if stat.st_size > max_size:
                    continue
                
                hash_val = compute_file_hash(file_path) if compute_hashes else None
                
                # Parse prefetch header
                with open(file_path, 'rb') as f:
                    data = f.read(100)
                
                metadata = {"filename": file_path.name}
                if len(data) >= 8:
                    try:
                        version = struct.unpack('<I', data[0:4])[0]
                        metadata['version'] = version
                    except:
                        pass
                
                artifact_id = f"pf_{hash_val[:16] if hash_val else file_path.stem}"
                
                artifact = Artifact(
                    id=artifact_id,
                    artifact_type=ArtifactType.PREFETCH,
                    source_path=file_path,
                    file_size=stat.st_size,
                    hash_val=hash_val,
                    created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc) if hasattr(stat, 'st_ctime') else None,
                    modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc) if hasattr(stat, 'st_atime') else None,
                    metadata=metadata,
                    collector_name=self.name
                )
                
                artifacts.append(artifact)
                print(f"  Found: {file_path.name} ({format_bytes(stat.st_size)})")
                
            except Exception as e:
                if options.get('verbose'):
                    print(f"  Error scanning {file_path}: {e}")
                continue
        
        return artifacts


class EventLogScanner:
    """Scanner for Windows Event Log files (.evtx)"""
    
    def __init__(self):
        self.name = "event_log_scanner"
    
    def can_collect(self, source: Path) -> bool:
        if source.is_file():
            return source.suffix.lower() == '.evtx' and self._is_valid_evtx(source)
        elif source.is_dir():
            for item in source.rglob("*.evtx"):
                if self._is_valid_evtx(item):
                    return True
            return False
        return False
    
    def _is_valid_evtx(self, path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                header = f.read(8)
                return header[:7] == b'ElfFile'
        except:
            return False
    
    def collect(self, source: Path, options: Dict) -> List[Artifact]:
        artifacts = []
        max_size = options.get('max_file_size', 100 * 1024 * 1024)
        compute_hashes = options.get('compute_hashes', True)
        
        files_to_scan = []
        
        if source.is_file():
            files_to_scan.append(source)
        elif source.is_dir():
            for file_path in source.rglob("*.evtx"):
                if self._is_valid_evtx(file_path):
                    files_to_scan.append(file_path)
        
        for file_path in files_to_scan:
            try:
                stat = file_path.stat()
                if stat.st_size > max_size:
                    continue
                
                hash_val = compute_file_hash(file_path) if compute_hashes else None
                
                artifact_id = f"evtx_{hash_val[:16] if hash_val else file_path.stem}"
                
                artifact = Artifact(
                    id=artifact_id,
                    artifact_type=ArtifactType.EVENT_LOG,
                    source_path=file_path,
                    file_size=stat.st_size,
                    hash_val=hash_val,
                    created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc) if hasattr(stat, 'st_ctime') else None,
                    modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc) if hasattr(stat, 'st_atime') else None,
                    metadata={"log_name": file_path.stem},
                    collector_name=self.name
                )
                
                artifacts.append(artifact)
                print(f"  Found: {file_path.name} ({format_bytes(stat.st_size)})")
                
            except Exception as e:
                if options.get('verbose'):
                    print(f"  Error scanning {file_path}: {e}")
                continue
        
        return artifacts


class LNKFileScanner:
    """Scanner for Windows Shortcut files (.lnk)"""
    
    def __init__(self):
        self.name = "lnk_scanner"
    
    def can_collect(self, source: Path) -> bool:
        if source.is_file():
            return source.suffix.lower() == '.lnk' and self._is_valid_lnk(source)
        elif source.is_dir():
            for item in source.rglob("*.lnk"):
                return True
            return False
        return False
    
    def _is_valid_lnk(self, path: Path) -> bool:
        try:
            with open(path, 'rb') as f:
                # LNK files start with specific GUID bytes
                header = f.read(20)
                return len(header) >= 20 and header[0] == 0x4C and header[4:8] == b'\x00\x00\x00\x00'
        except:
            return False
    
    def collect(self, source: Path, options: Dict) -> List[Artifact]:
        artifacts = []
        max_size = options.get('max_file_size', 100 * 1024 * 1024)
        compute_hashes = options.get('compute_hashes', True)
        
        files_to_scan = []
        
        if source.is_file():
            files_to_scan.append(source)
        elif source.is_dir():
            for file_path in source.rglob("*.lnk"):
                files_to_scan.append(file_path)
        
        for file_path in files_to_scan:
            try:
                stat = file_path.stat()
                if stat.st_size > max_size:
                    continue
                
                hash_val = compute_file_hash(file_path) if compute_hashes else None
                
                artifact_id = f"lnk_{hash_val[:16] if hash_val else file_path.stem}"
                
                artifact = Artifact(
                    id=artifact_id,
                    artifact_type=ArtifactType.LNK_FILE,
                    source_path=file_path,
                    file_size=stat.st_size,
                    hash_val=hash_val,
                    created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc) if hasattr(stat, 'st_ctime') else None,
                    modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc) if hasattr(stat, 'st_atime') else None,
                    metadata={"shortcut_name": file_path.stem},
                    collector_name=self.name
                )
                
                artifacts.append(artifact)
                print(f"  Found: {file_path.name} ({format_bytes(stat.st_size)})")
                
            except Exception as e:
                if options.get('verbose'):
                    print(f"  Error scanning {file_path}: {e}")
                continue
        
        return artifacts


class BrowserHistoryScanner:
    """Scanner for Browser History databases (Chrome, Edge, Firefox)"""
    
    def __init__(self):
        self.name = "browser_history_scanner"
        self.history_patterns = [
            '**/History',           # Chrome, Edge
            '**/places.sqlite',     # Firefox
            '**/Cookies',           # Browser cookies
            '**/Login Data',        # Saved passwords
        ]
    
    def can_collect(self, source: Path) -> bool:
        if source.is_file():
            return self._is_browser_db(source)
        elif source.is_dir():
            for pattern in self.history_patterns:
                for item in source.rglob(pattern.split('/')[-1]):
                    if self._is_browser_db(item):
                        return True
            return False
        return False
    
    def _is_browser_db(self, path: Path) -> bool:
        name = path.name.lower()
        return name in ['history', 'places.sqlite', 'cookies', 'login data', 'favicons', 'bookmarks']
    
    def collect(self, source: Path, options: Dict) -> List[Artifact]:
        artifacts = []
        max_size = options.get('max_file_size', 500 * 1024 * 1024)
        compute_hashes = options.get('compute_hashes', True)
        
        files_to_scan = []
        
        if source.is_file():
            files_to_scan.append(source)
        elif source.is_dir():
            for pattern in self.history_patterns:
                for file_path in source.rglob(pattern.split('/')[-1]):
                    if self._is_browser_db(file_path):
                        files_to_scan.append(file_path)
        
        for file_path in files_to_scan:
            try:
                stat = file_path.stat()
                if stat.st_size > max_size:
                    continue
                
                hash_val = compute_file_hash(file_path) if compute_hashes else None
                
                # Determine browser type from path
                browser_type = "Unknown"
                path_str = str(file_path).lower()
                if 'chrome' in path_str or 'google' in path_str:
                    browser_type = "Chrome"
                elif 'edge' in path_str or 'microsoft' in path_str:
                    browser_type = "Edge"
                elif 'firefox' in path_str or 'mozilla' in path_str:
                    browser_type = "Firefox"
                elif 'brave' in path_str:
                    browser_type = "Brave"
                elif 'opera' in path_str:
                    browser_type = "Opera"
                
                artifact_id = f"browser_{hash_val[:16] if hash_val else file_path.stem}"
                
                artifact = Artifact(
                    id=artifact_id,
                    artifact_type=ArtifactType.BROWSER_HISTORY,
                    source_path=file_path,
                    file_size=stat.st_size,
                    hash_val=hash_val,
                    created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc) if hasattr(stat, 'st_ctime') else None,
                    modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc) if hasattr(stat, 'st_atime') else None,
                    metadata={
                        "browser": browser_type,
                        "db_type": file_path.name
                    },
                    collector_name=self.name
                )
                
                artifacts.append(artifact)
                print(f"  Found: {file_path.name} ({format_bytes(stat.st_size)}) - {browser_type}")
                
            except Exception as e:
                if options.get('verbose'):
                    print(f"  Error scanning {file_path}: {e}")
                continue
        
        return artifacts


class GenericFileScanner:
    """Scanner for all files (generic)"""
    
    def __init__(self):
        self.name = "generic_scanner"
    
    def can_collect(self, source: Path) -> bool:
        return source.exists()
    
    def collect(self, source: Path, options: Dict) -> List[Artifact]:
        artifacts = []
        max_size = options.get('max_file_size', 100 * 1024 * 1024)
        compute_hashes = options.get('compute_hashes', True)
        max_depth = options.get('max_depth')
        
        files_to_scan = []
        
        if source.is_file():
            files_to_scan.append(source)
        elif source.is_dir():
            for root, dirs, files in os.walk(source):
                current_depth = len(Path(root).relative_to(source).parts)
                if max_depth and current_depth > max_depth:
                    dirs[:] = []
                    continue
                
                for filename in files:
                    file_path = Path(root) / filename
                    files_to_scan.append(file_path)
        
        for file_path in files_to_scan:
            try:
                stat = file_path.stat()
                if stat.st_size > max_size:
                    continue
                
                hash_val = compute_file_hash(file_path) if compute_hashes else None
                
                # Detect file type
                file_category, mime_type, file_type_desc = detect_file_type(file_path)
                
                artifact_id = f"file_{hash_val[:16] if hash_val else file_path.stem}"
                
                artifact = Artifact(
                    id=artifact_id,
                    artifact_type=ArtifactType.GENERIC_FILE,
                    source_path=file_path,
                    file_size=stat.st_size,
                    hash_val=hash_val,
                    created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc) if hasattr(stat, 'st_ctime') else None,
                    modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc) if hasattr(stat, 'st_atime') else None,
                    metadata={
                        "file_extension": file_path.suffix,
                        "file_category": file_category,
                        "mime_type": mime_type,
                        "file_type": file_type_desc
                    },
                    collector_name=self.name
                )
                
                artifacts.append(artifact)
                print(f"  Found: {file_path.name} ({format_bytes(stat.st_size)}) - {file_type_desc}")
                
            except Exception as e:
                if options.get('verbose'):
                    print(f"  Error scanning {file_path}: {e}")
                continue
        
        return artifacts


class ForensicOrchestrator:
    """Orchestrates forensic collection"""
    
    def __init__(self, concurrency: int = 4, enabled_collectors: Optional[List[str]] = None):
        all_collectors = [
            RegistryScanner(),
            PrefetchScanner(),
            EventLogScanner(),
            LNKFileScanner(),
            BrowserHistoryScanner(),
            GenericFileScanner(),
        ]
        
        if enabled_collectors:
            self.collectors = [c for c in all_collectors if c.name in enabled_collectors]
        else:
            self.collectors = all_collectors
        
        self.concurrency = concurrency
    
    def list_collectors(self) -> List[Tuple[str, List[str]]]:
        """List available collectors"""
        collector_types = {
            'registry_scanner': [ArtifactType.REGISTRY_HIVE],
            'prefetch_scanner': [ArtifactType.PREFETCH],
            'event_log_scanner': [ArtifactType.EVENT_LOG],
            'lnk_scanner': [ArtifactType.LNK_FILE],
            'browser_history_scanner': [ArtifactType.BROWSER_HISTORY],
        }
        return [(c.name, collector_types.get(c.name, [ArtifactType.GENERIC_FILE])) for c in self.collectors]
    
    def find_compatible_collectors(self, source: Path) -> List[Any]:
        """Find collectors that can handle the source"""
        return [c for c in self.collectors if c.can_collect(source)]
    
    def execute(self, sources: List[Path], options: Dict) -> Dict:
        """Execute triage operation"""
        start_time = datetime.now(timezone.utc)
        all_artifacts = []
        errors = []
        
        print(f"\nStarting forensic triage...")
        print(f"Sources: {[str(s) for s in sources]}")
        print(f"Concurrency: {self.concurrency}")
        
        for source in sources:
            print(f"\nProcessing: {source}")
            
            compatible = self.find_compatible_collectors(source)
            if not compatible:
                print(f"  No compatible collectors found")
                continue
            
            for collector in compatible:
                print(f"  Running: {collector.name}")
                try:
                    artifacts = collector.collect(source, options)
                    all_artifacts.extend(artifacts)
                    print(f"  Collected {len(artifacts)} artifacts")
                except Exception as e:
                    print(f"  Error: {e}")
                    errors.append(str(e))
        
        end_time = datetime.now(timezone.utc)
        
        # Deduplicate by ID
        seen_ids = set()
        unique_artifacts = []
        for a in all_artifacts:
            if a.id not in seen_ids:
                seen_ids.add(a.id)
                unique_artifacts.append(a)
        
        return {
            "start_time": start_time,
            "end_time": end_time,
            "artifacts_collected": len(unique_artifacts),
            "artifacts": unique_artifacts,
            "errors": errors
        }


def generate_csv_report(result: Dict, output_path: Path) -> None:
    """Generate CSV report of artifacts"""
    fieldnames = ['id', 'artifact_type', 'source_path', 'file_size_bytes', 'file_size_human',
                  'hash_sha256', 'created_at', 'modified_at', 'accessed_at', 'collector', 'metadata']
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for artifact in result['artifacts']:
            d = artifact.to_dict()
            # Convert metadata dict to string for CSV
            d['metadata'] = json.dumps(d['metadata'])
            writer.writerow(d)
    
    print(f"  CSV report: {output_path}")


def generate_manifest(result: Dict) -> Dict:
    return {
        "case_info": {
            "tool_name": "Zscan (Python Edition)",
            "tool_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_format": "evidence_manifest_v1"
        },
        "triage_summary": {
            "start_time": result['start_time'].isoformat(),
            "end_time": result['end_time'].isoformat(),
            "total_artifacts": result['artifacts_collected'],
            "total_errors": len(result['errors']),
            "duration_seconds": int((result['end_time'] - result['start_time']).total_seconds())
        },
        "artifacts": [a.to_dict() for a in result['artifacts']]
    }


def generate_markdown_report(result: Dict) -> str:
    """Generate Markdown report"""
    lines = []
    lines.append("# Zscan Evidence Report\n")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n")
    
    # Summary
    lines.append("## Summary\n")
    lines.append(f"- **Start Time:** {result['start_time'].isoformat()}")
    lines.append(f"- **End Time:** {result['end_time'].isoformat()}")
    lines.append(f"- **Duration:** {int((result['end_time'] - result['start_time']).total_seconds())} seconds")
    lines.append(f"- **Total Artifacts:** {result['artifacts_collected']}")
    lines.append(f"- **Errors:** {len(result['errors'])}\n")
    
    # Artifacts by type
    lines.append("## Artifacts by Type\n")
    type_counts = {}
    for a in result['artifacts']:
        t = a.artifact_type
        type_counts[t] = type_counts.get(t, 0) + 1
    
    for artifact_type, count in type_counts.items():
        lines.append(f"- **{artifact_type}:** {count}")
    lines.append("")
    
    # Detailed findings
    lines.append("## Detailed Findings\n")
    for idx, artifact in enumerate(result['artifacts'], 1):
        lines.append(f"### {idx}. {artifact.id}\n")
        lines.append(f"- **Type:** {artifact.artifact_type}")
        lines.append(f"- **Source:** `{artifact.source_path}`")
        lines.append(f"- **Size:** {format_bytes(artifact.file_size)} ({artifact.file_size} bytes)")
        
        if artifact.hash:
            lines.append(f"- **SHA-256:** `{artifact.hash}`")
        if artifact.created_at:
            lines.append(f"- **Created:** {artifact.created_at.isoformat()}")
        if artifact.modified_at:
            lines.append(f"- **Modified:** {artifact.modified_at.isoformat()}")
        if artifact.accessed_at:
            lines.append(f"- **Accessed:** {artifact.accessed_at.isoformat()}")
        
        lines.append(f"- **Collector:** {artifact.collector_name}")
        
        # Metadata
        if artifact.metadata.get('hive_type'):
            lines.append(f"- **Hive Type:** {artifact.metadata['hive_type']}")
        if artifact.metadata.get('last_written'):
            lines.append(f"- **Last Written:** {artifact.metadata['last_written']}")
        
        lines.append("")
    
    # Errors
    if result['errors']:
        lines.append("## Errors\n")
        for idx, error in enumerate(result['errors'], 1):
            lines.append(f"{idx}. {error}\n")
    
    lines.append("---\n")
    lines.append("*Generated by Zscan (Python Edition) - Digital Forensics Triage Tool*\n")
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Zscan v2.0 - Digital Forensics Triage Tool (Python Edition)"
    )
    parser.add_argument('-s', '--source', nargs='+',
                        help='Source path(s) to scan')
    parser.add_argument('-o', '--output', default='./zscan-output',
                        help='Output directory (default: ./zscan-output)')
    parser.add_argument('--max-size', type=int, default=100,
                        help='Maximum file size in MB (default: 100)')
    parser.add_argument('--no-hash', action='store_true',
                        help='Disable SHA-256 hashing')
    parser.add_argument('--max-depth', type=int,
                        help='Maximum recursion depth')
    parser.add_argument('-c', '--concurrency', type=int, default=4,
                        help='Concurrency limit (default: 4)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    parser.add_argument('--list-collectors', action='store_true',
                        help='List available collectors')
    parser.add_argument('--collectors', type=str,
                        help='Comma-separated list of collectors to use (default: all)')
    parser.add_argument('--csv', action='store_true',
                        help='Also generate CSV report')
    parser.add_argument('--format', choices=['json', 'csv', 'all'], default='all',
                        help='Output format (default: all)')
    
    args = parser.parse_args()
    
    if args.list_collectors:
        orchestrator = ForensicOrchestrator()
        print("\nAvailable Collectors:")
        print(f"{'Name':<25} {'Artifact Types'}")
        print("-" * 70)
        for name, types in orchestrator.list_collectors():
            print(f"{name:<25} {', '.join(types)}")
        print()
        return
    
    if not args.source:
        print("Error: No source path specified. Use --source or run 'zscan.py --list-collectors'")
        sys.exit(1)
    
    # Parse enabled collectors
    enabled_collectors = None
    if args.collectors:
        enabled_collectors = [c.strip() for c in args.collectors.split(',')]
    
    # Build options
    options = {
        'compute_hashes': not args.no_hash,
        'max_file_size': args.max_size * 1024 * 1024,
        'max_depth': args.max_depth,
        'follow_symlinks': False,
        'verbose': args.verbose
    }
    
    # Parse sources
    sources = [Path(s) for s in args.source]
    output_dir = Path(args.output)
    
    # Validate sources
    for source in sources:
        if not source.exists():
            print(f"Error: Source does not exist: {source}")
            sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Execute triage
    orchestrator = ForensicOrchestrator(concurrency=args.concurrency, enabled_collectors=enabled_collectors)
    result = orchestrator.execute(sources, options)
    
    # Generate reports based on format
    if args.format in ['json', 'all']:
        manifest = generate_manifest(result)
        manifest_path = output_dir / "evidence_manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"  JSON manifest: {manifest_path}")
    
    if args.format in ['csv', 'all'] or args.csv:
        csv_path = output_dir / "evidence_report.csv"
        generate_csv_report(result, csv_path)
    
    if args.format in ['json', 'all']:
        report = generate_markdown_report(result)
        report_path = output_dir / "forensics_report.md"
        with open(report_path, 'w') as f:
            f.write(report)
        print(f"  Markdown report: {report_path}")
    
    # Print summary
    print("\n" + "=" * 50)
    print("      Zscan v2.0 - Triage Complete")
    print("=" * 50)
    print(f"  Artifacts Found: {result['artifacts_collected']}")
    
    # Show breakdown by type
    if result['artifacts']:
        type_counts = Counter(a.artifact_type for a in result['artifacts'])
        print("\n  Breakdown:")
        for atype, count in type_counts.most_common():
            print(f"    - {atype}: {count}")
    
    print(f"\n  Duration: {int((result['end_time'] - result['start_time']).total_seconds())} seconds")
    if result['errors']:
        print(f"  Errors: {len(result['errors'])}")
    print(f"\n  Reports saved to: {output_dir}")
    print("=" * 50)


if __name__ == "__main__":
    main()
