from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CandidateArtifact:
    path: str
    kind: str
    size: int
    sha256: Optional[str] = None
    format_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DirectorySnapshot:
    path: str
    directory_names: List[str] = field(default_factory=list)
    file_names: List[str] = field(default_factory=list)
    file_extension_counts: Dict[str, int] = field(default_factory=dict)
    entries_sampled: int = 0
    truncated: bool = False
    file_names_redacted: bool = False


@dataclass(frozen=True)
class ProfileMatch:
    profile_id: str
    display_name: str
    score: int
    confidence: str
    matched_markers: List[str] = field(default_factory=list)
    missing_markers: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DiskPartitionInfo:
    partition_number: Optional[int] = None
    drive_letter: Optional[str] = None
    offset: Optional[int] = None
    size: Optional[int] = None
    partition_type: Optional[str] = None
    gpt_type: Optional[str] = None
    mbr_type: Optional[str] = None
    is_active: Optional[bool] = None
    is_boot: Optional[bool] = None
    is_system: Optional[bool] = None
    filesystem: Optional[str] = None
    filesystem_label: Optional[str] = None


@dataclass(frozen=True)
class PhysicalMapping:
    disk_number: Optional[int] = None
    partition_number: Optional[int] = None
    disk_name: Optional[str] = None
    bus_type: Optional[str] = None
    partition_style: Optional[str] = None
    disk_size: Optional[int] = None
    partition_size: Optional[int] = None
    partition_offset: Optional[int] = None
    is_boot: Optional[bool] = None
    is_system: Optional[bool] = None
    serial_number: Optional[str] = None
    disk_unique_id: Optional[str] = None
    logical_sector_size: Optional[int] = None
    physical_sector_size: Optional[int] = None
    is_read_only: Optional[bool] = None
    is_offline: Optional[bool] = None
    disk_health: Optional[str] = None
    disk_operational_status: Optional[str] = None
    filesystem: Optional[str] = None
    filesystem_label: Optional[str] = None
    drive_type: Optional[str] = None
    volume_health: Optional[str] = None
    partitions: List[DiskPartitionInfo] = field(default_factory=list)
    mapping_backend: Optional[str] = None
    mapping_error: Optional[str] = None


@dataclass(frozen=True)
class ImagingPlan:
    source_path: str
    selected_root: str
    disk_number: int
    disk_name: str
    source_size: int
    destination: str
    manifest_path: str
    confirmation_phrase: str
    profile_id: str
    profile_score: int
    structure_sha256: str
    bus_type: Optional[str] = None
    drive_type: Optional[str] = None
    partition_style: Optional[str] = None
    source_serial_sha256: Optional[str] = None
    source_unique_id_sha256: Optional[str] = None
    selected_partition_number: Optional[int] = None
    selected_partition_offset: Optional[int] = None
    selected_partition_size: Optional[int] = None
    logical_sector_size: Optional[int] = None
    physical_sector_size: Optional[int] = None
    source_partition_layout_sha256: Optional[str] = None
    source_identity_sha256: Optional[str] = None
    overwrite_existing: bool = False


@dataclass(frozen=True)
class ImageResult:
    image_path: str
    manifest_path: str
    bytes_written: int
    streaming_sha256: str
    reread_sha256: str
    verified: bool
    started_at_utc: str
    completed_at_utc: str


@dataclass
class ProbeReport:
    schema_version: int
    generated_at_utc: str
    platform: str
    selected_root: str
    volume_total: Optional[int]
    volume_used: Optional[int]
    volume_free: Optional[int]
    root_entries: List[Dict[str, Any]]
    directory_snapshots: List[DirectorySnapshot]
    profile: ProfileMatch
    profile_candidates: List[ProfileMatch]
    physical_mapping: PhysicalMapping
    candidate_artifacts: List[CandidateArtifact]
    warnings: List[str]
    structure_sha256: str
    probe_status: str = "COMPLETE"
    read_errors: List[str] = field(default_factory=list)
    probe_policy: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
