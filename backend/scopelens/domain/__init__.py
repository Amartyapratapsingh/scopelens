"""Typed domain records for ScopeLens.

These are the Pydantic records named in Build Plan §4. They are transport- and
storage-agnostic: the SQLAlchemy models in ``scopelens.persistence`` persist them,
and the API in ``scopelens.api`` validates against them.
"""

from scopelens.domain.enums import (
    AuthorityDomain,
    Category,
    ControlOutcome,
    EvidenceStatus,
    ProfileName,
    ReviewState,
    ScanStatus,
)
from scopelens.domain.lab import (
    LabBinding,
    LabBindingError,
    LabService,
    LabServiceAllowlist,
    load_lab_services,
)
from scopelens.domain.registry import (
    CheckRegistry,
    CheckRegistryEntry,
    RegistryError,
    load_registry,
)
from scopelens.domain.scan import (
    ExecutionState,
    Scan,
    ScanCreateRequest,
    ScanRecord,
)
from scopelens.domain.scope import (
    DEFAULT_ALLOWED_METHODS,
    LabScopeCreate,
    ProductionScopeCreate,
    ScopeVersion,
    compute_scope_hash,
    default_port,
    normalize_host,
)

__all__ = [
    "DEFAULT_ALLOWED_METHODS",
    "AuthorityDomain",
    "Category",
    "CheckRegistry",
    "CheckRegistryEntry",
    "ControlOutcome",
    "EvidenceStatus",
    "ExecutionState",
    "LabBinding",
    "LabBindingError",
    "LabScopeCreate",
    "LabService",
    "LabServiceAllowlist",
    "ProductionScopeCreate",
    "ProfileName",
    "RegistryError",
    "ReviewState",
    "Scan",
    "ScanCreateRequest",
    "ScanRecord",
    "ScanStatus",
    "ScopeVersion",
    "compute_scope_hash",
    "default_port",
    "load_lab_services",
    "load_registry",
    "normalize_host",
]
