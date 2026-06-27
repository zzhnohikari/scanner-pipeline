"""Lightweight contracts shared by scanner pipeline modules."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class TargetItem:
    host: str
    port: int = 0
    scheme: str = "http"
    source: str = "input"


@dataclass
class JSAsset:
    url: str
    final_url: str = ""
    status: int = 0
    content_type: str = ""
    source: str = ""
    size: int = 0


@dataclass
class JSGraphEdge:
    src: str
    dst: str
    type: str


@dataclass
class APIEndpoint:
    path: str
    source: str = "js"
    confidence: float = 0.7


@dataclass
class JSGraphResult:
    assets: List[JSAsset] = field(default_factory=list)
    edges: List[JSGraphEdge] = field(default_factory=list)
    apis: List[APIEndpoint] = field(default_factory=list)
    prefixes: Set[str] = field(default_factory=set)
    sensitive: Set[str] = field(default_factory=set)
    param_profile: Dict[str, Any] = field(default_factory=dict)
    discovered_urls: Set[str] = field(default_factory=set)
    attempted_urls: Set[str] = field(default_factory=set)
    successful_urls: Set[str] = field(default_factory=set)
    skipped_common_urls: Set[str] = field(default_factory=set)
    stats: Dict[str, Any] = field(default_factory=dict)

    def api_paths(self):
        return {api.path for api in self.apis if api.path}
