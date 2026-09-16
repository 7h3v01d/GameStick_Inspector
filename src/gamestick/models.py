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
    source_consistency_status: str = "NOT_REQUESTED"
    second_source_sha256: Optional[str] = None
    second_source_bytes_read: int = 0
    second_source_error_category: Optional[str] = None


@dataclass(frozen=True)
class LauncherCandidate:
    path: str
    format_name: str
    score: int
    confidence: str
    role_hints: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ContentRootHint:
    path: str
    role: str
    score: int
    evidence: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DeviceProfileCandidate:
    schema_version: int
    candidate_id: str
    status: str
    base_profile_id: str
    base_profile_score: int
    launcher_resolution: str
    launcher_path: Optional[str]
    launcher_format: Optional[str]
    launcher_confidence: str
    launcher_candidates: List[LauncherCandidate] = field(default_factory=list)
    content_roots: List[ContentRootHint] = field(default_factory=list)
    platform_directories: List[str] = field(default_factory=list)
    profile_signature_sha256: str = ""
    notes: List[str] = field(default_factory=list)




@dataclass(frozen=True)
class BinaryFingerprintEvidence:
    schema_version: int
    sample_strategy: str
    sample_window_bytes: int
    sampled_window_count: int
    sampled_bytes_total: int
    unique_sampled_bytes: int
    sample_covers_entire_file: bool
    short_read_window_count: int = 0
    windows: List[Dict[str, Any]] = field(default_factory=list)
    prefix_sha256: Optional[str] = None
    tail_sha256: Optional[str] = None
    header_signatures: List[str] = field(default_factory=list)
    sampled_signature_hits: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    structural_token_hits: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    entropy_bits_per_byte: float = 0.0
    printable_ratio_ppm: int = 0
    nul_ratio_ppm: int = 0
    arbitrary_strings_exported: bool = False
    full_file_scan_performed: bool = False


@dataclass(frozen=True)
class DatContainerEvidence:
    path: str
    role: str
    size: int
    container_format: str
    central_directory_valid: bool
    declared_member_count: Optional[int] = None
    file_member_count: int = 0
    directory_member_count: int = 0
    central_directory_size: Optional[int] = None
    zip_comment_length: Optional[int] = None
    control_members: List[str] = field(default_factory=list)
    member_extension_counts: Dict[str, int] = field(default_factory=dict)
    compression_method_counts: Dict[str, int] = field(default_factory=dict)
    encrypted_member_count: int = 0
    undecodable_member_name_count: int = 0
    member_names_redacted: bool = True
    binary_fingerprint: Optional[BinaryFingerprintEvidence] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class NumberedDatProfileCandidate:
    schema_version: int
    candidate_id: str
    status: str
    confidence: str
    heuristic_score: int
    profile_family: str
    root_dat_present: bool
    numbered_directory_count: int
    matched_numbered_dat_count: int
    zip_numbered_dat_count: int
    wqw_numbered_dat_count: int
    damaged_wqw_numbered_dat_count: int
    filelist_control_count: int
    structural_signature_sha256: str
    binary_fingerprint_count: int = 0
    binary_family_assessment: str = "unknown"
    numbered_catalog_common_prefix_bytes: int = 0
    root_matches_numbered_prefix_bytes: int = 0
    common_header_signatures: List[str] = field(default_factory=list)
    common_sampled_signatures: List[str] = field(default_factory=list)
    root_catalog: Optional[DatContainerEvidence] = None
    numbered_catalogs: List[DatContainerEvidence] = field(default_factory=list)
    catalogue_codes: List[str] = field(default_factory=list)
    member_names_redacted: bool = True
    catalogue_relationships: Dict[str, Any] = field(default_factory=dict)
    catalogue_consistency: Dict[str, Any] = field(default_factory=dict)
    read_stability: Dict[str, Any] = field(default_factory=dict)
    longitudinal_integrity: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)


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
    device_profile_candidate: Optional[DeviceProfileCandidate] = None
    numbered_dat_profile: Optional[NumberedDatProfileCandidate] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
