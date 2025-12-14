"""
Backup storage management with hierarchical organization.

Storage structure:
  sites/
    <region>/
      <site>/
        <building>/
          floor-<floor>/
            room-<room>/
              rack-<rack>/
                u<position>/
                  <device_hostname>/
                    <backup_type>/
                      <timestamp>_<backup_type>.<ext>[.gz|.bz2]

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import os
import gzip
import bz2
import lzma
import json
import hashlib
import shutil
from datetime import datetime
from pathlib import Path
from typing import Iterator

from globaldetect.backup.models import (
    BackupJob,
    BackupResult,
    BackupType,
    CompressionType,
    DeviceLocation,
    BackupStatus,
)


class BackupStorage:
    """Manages backup file storage with hierarchical organization."""

    def __init__(self, base_path: str | Path):
        """Initialize storage with base path.

        Args:
            base_path: Root directory for all backups
        """
        self.base_path = Path(base_path)
        self.sites_path = self.base_path / "sites"
        self.metadata_path = self.base_path / "metadata"
        self.index_path = self.base_path / "index"

    def initialize(self) -> None:
        """Create the base directory structure."""
        self.sites_path.mkdir(parents=True, exist_ok=True)
        self.metadata_path.mkdir(parents=True, exist_ok=True)
        self.index_path.mkdir(parents=True, exist_ok=True)

        # Create index files
        jobs_index = self.index_path / "jobs.json"
        if not jobs_index.exists():
            jobs_index.write_text("[]")

        results_index = self.index_path / "results.json"
        if not results_index.exists():
            results_index.write_text("[]")

    def get_device_path(
        self,
        hostname: str,
        location: DeviceLocation | None = None
    ) -> Path:
        """Get the storage path for a device.

        Args:
            hostname: Device hostname
            location: Physical location information

        Returns:
            Path to the device's backup directory
        """
        if location:
            loc_path = location.to_path()
        else:
            loc_path = "unknown"

        # Sanitize hostname for filesystem
        safe_hostname = self._sanitize_name(hostname)

        return self.sites_path / loc_path / safe_hostname

    def get_backup_path(
        self,
        hostname: str,
        backup_type: BackupType,
        location: DeviceLocation | None = None,
        timestamp: datetime | None = None,
        compression: CompressionType = CompressionType.NONE,
    ) -> Path:
        """Get the full path for a backup file.

        Args:
            hostname: Device hostname
            backup_type: Type of backup
            location: Physical location
            timestamp: Backup timestamp (defaults to now)
            compression: Compression type

        Returns:
            Full path to the backup file
        """
        device_path = self.get_device_path(hostname, location)
        type_path = device_path / backup_type.value

        if timestamp is None:
            timestamp = datetime.now()

        # Format: 20241214_143052_full.conf.gz
        ts_str = timestamp.strftime("%Y%m%d_%H%M%S")
        filename = f"{ts_str}_{backup_type.value}.conf"

        # Add compression extension
        if compression == CompressionType.GZIP:
            filename += ".gz"
        elif compression == CompressionType.BZIP2:
            filename += ".bz2"
        elif compression == CompressionType.XZ:
            filename += ".xz"
        elif compression == CompressionType.ZSTD:
            filename += ".zst"

        return type_path / filename

    def save_backup(
        self,
        content: str | bytes,
        hostname: str,
        backup_type: BackupType,
        location: DeviceLocation | None = None,
        compression: CompressionType = CompressionType.GZIP,
        timestamp: datetime | None = None,
    ) -> tuple[Path, int]:
        """Save backup content to storage.

        Args:
            content: Configuration content
            hostname: Device hostname
            backup_type: Type of backup
            location: Physical location
            compression: Compression to apply
            timestamp: Backup timestamp

        Returns:
            Tuple of (path to saved file, size in bytes)
        """
        if timestamp is None:
            timestamp = datetime.now()

        backup_path = self.get_backup_path(
            hostname, backup_type, location, timestamp, compression
        )

        # Ensure directory exists
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to bytes if string
        if isinstance(content, str):
            content = content.encode('utf-8')

        # Save with compression
        if compression == CompressionType.GZIP:
            with gzip.open(backup_path, 'wb', compresslevel=9) as f:
                f.write(content)
        elif compression == CompressionType.BZIP2:
            with bz2.open(backup_path, 'wb', compresslevel=9) as f:
                f.write(content)
        elif compression == CompressionType.XZ:
            with lzma.open(backup_path, 'wb', preset=9) as f:
                f.write(content)
        else:
            backup_path.write_bytes(content)

        # Calculate checksum
        file_hash = hashlib.sha256(backup_path.read_bytes()).hexdigest()

        # Save metadata
        meta_path = backup_path.with_suffix(backup_path.suffix + ".meta.json")
        metadata = {
            "hostname": hostname,
            "backup_type": backup_type.value,
            "compression": compression.value,
            "timestamp": timestamp.isoformat(),
            "sha256": file_hash,
            "original_size": len(content),
            "compressed_size": backup_path.stat().st_size,
            "location": location.to_dict() if location else None,
        }
        meta_path.write_text(json.dumps(metadata, indent=2))

        return backup_path, backup_path.stat().st_size

    def load_backup(self, path: Path) -> bytes:
        """Load and decompress backup content.

        Args:
            path: Path to backup file

        Returns:
            Decompressed backup content
        """
        suffix = path.suffix.lower()

        if suffix == ".gz":
            with gzip.open(path, 'rb') as f:
                return f.read()
        elif suffix == ".bz2":
            with bz2.open(path, 'rb') as f:
                return f.read()
        elif suffix == ".xz":
            with lzma.open(path, 'rb') as f:
                return f.read()
        else:
            return path.read_bytes()

    def list_backups(
        self,
        hostname: str | None = None,
        location: DeviceLocation | None = None,
        backup_type: BackupType | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> Iterator[dict]:
        """List available backups with optional filtering.

        Args:
            hostname: Filter by device hostname
            location: Filter by location
            backup_type: Filter by backup type
            since: Only backups after this time
            until: Only backups before this time

        Yields:
            Backup metadata dictionaries
        """
        search_path = self.sites_path

        if hostname and location:
            search_path = self.get_device_path(hostname, location)

        # Find all .meta.json files
        for meta_file in search_path.rglob("*.meta.json"):
            try:
                metadata = json.loads(meta_file.read_text())

                # Apply filters
                if hostname and metadata.get("hostname") != hostname:
                    continue

                if backup_type and metadata.get("backup_type") != backup_type.value:
                    continue

                ts = datetime.fromisoformat(metadata["timestamp"])
                if since and ts < since:
                    continue
                if until and ts > until:
                    continue

                # Add file path
                backup_file = meta_file.with_suffix("")  # Remove .meta.json
                backup_file = backup_file.with_suffix("")  # Remove .meta
                metadata["path"] = str(backup_file)

                yield metadata
            except (json.JSONDecodeError, KeyError):
                continue

    def get_latest_backup(
        self,
        hostname: str,
        backup_type: BackupType,
        location: DeviceLocation | None = None,
    ) -> dict | None:
        """Get the most recent backup for a device.

        Args:
            hostname: Device hostname
            backup_type: Type of backup
            location: Physical location

        Returns:
            Backup metadata or None if not found
        """
        backups = list(self.list_backups(
            hostname=hostname,
            location=location,
            backup_type=backup_type,
        ))

        if not backups:
            return None

        # Sort by timestamp descending
        backups.sort(
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

        return backups[0]

    def cleanup_old_backups(
        self,
        hostname: str,
        location: DeviceLocation | None = None,
        retention_days: int | None = None,
        retention_count: int | None = None,
    ) -> int:
        """Remove old backups based on retention policy.

        Args:
            hostname: Device hostname
            location: Physical location
            retention_days: Remove backups older than this
            retention_count: Keep only this many most recent

        Returns:
            Number of backups removed
        """
        removed = 0
        device_path = self.get_device_path(hostname, location)

        if not device_path.exists():
            return 0

        # Group backups by type
        for type_dir in device_path.iterdir():
            if not type_dir.is_dir():
                continue

            backups = []
            for meta_file in type_dir.glob("*.meta.json"):
                try:
                    metadata = json.loads(meta_file.read_text())
                    metadata["meta_path"] = meta_file
                    backups.append(metadata)
                except (json.JSONDecodeError, KeyError):
                    continue

            # Sort by timestamp descending
            backups.sort(
                key=lambda x: x.get("timestamp", ""),
                reverse=True
            )

            now = datetime.now()

            for i, backup in enumerate(backups):
                should_remove = False

                # Check retention count
                if retention_count and i >= retention_count:
                    should_remove = True

                # Check retention days
                if retention_days:
                    ts = datetime.fromisoformat(backup["timestamp"])
                    age_days = (now - ts).days
                    if age_days > retention_days:
                        should_remove = True

                if should_remove:
                    meta_path = backup["meta_path"]
                    backup_path = Path(backup.get("path", ""))

                    # Remove backup file
                    if backup_path.exists():
                        backup_path.unlink()

                    # Remove metadata
                    if meta_path.exists():
                        meta_path.unlink()

                    removed += 1

        return removed

    def diff_configs(
        self,
        hostname: str,
        backup_type: BackupType,
        location: DeviceLocation | None = None,
    ) -> str | None:
        """Compare current backup with previous.

        Args:
            hostname: Device hostname
            backup_type: Type of backup
            location: Physical location

        Returns:
            Diff output or None if no previous backup
        """
        import difflib

        backups = list(self.list_backups(
            hostname=hostname,
            location=location,
            backup_type=backup_type,
        ))

        if len(backups) < 2:
            return None

        # Sort by timestamp descending
        backups.sort(
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )

        current = self.load_backup(Path(backups[0]["path"])).decode('utf-8')
        previous = self.load_backup(Path(backups[1]["path"])).decode('utf-8')

        diff = difflib.unified_diff(
            previous.splitlines(keepends=True),
            current.splitlines(keepends=True),
            fromfile=f"previous ({backups[1]['timestamp']})",
            tofile=f"current ({backups[0]['timestamp']})",
        )

        return "".join(diff)

    def get_storage_stats(self) -> dict:
        """Get storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        total_size = 0
        total_backups = 0
        devices = set()
        regions = set()

        for meta_file in self.sites_path.rglob("*.meta.json"):
            try:
                metadata = json.loads(meta_file.read_text())
                total_backups += 1
                total_size += metadata.get("compressed_size", 0)
                devices.add(metadata.get("hostname"))

                if metadata.get("location"):
                    regions.add(metadata["location"].get("region"))
            except (json.JSONDecodeError, KeyError):
                continue

        return {
            "total_backups": total_backups,
            "total_size_bytes": total_size,
            "total_size_human": self._human_size(total_size),
            "unique_devices": len(devices),
            "regions": len(regions),
        }

    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Sanitize a name for use in filesystem paths."""
        # Replace problematic characters
        safe = name.replace("/", "_").replace("\\", "_")
        safe = safe.replace(":", "_").replace(" ", "_")
        return safe.lower()

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
