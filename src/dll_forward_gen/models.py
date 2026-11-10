"""Data models for PE exports and binary metadata."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union


class PeArch(str, Enum):
    """Architecture of target PE binary."""
    X86 = "x86"
    X64 = "x64"
    ARM64 = "arm64"
    UNKNOWN = "unknown"

    @classmethod
    def from_machine(cls, machine: int) -> "PeArch":
        if machine == 0x014C:
            return cls.X86
        if machine == 0x8664:
            return cls.X64
        if machine == 0xAA64:
            return cls.ARM64
        return cls.UNKNOWN


@dataclass(frozen=True)
class PeMitigations:
    """Security mitigations extracted from DllCharacteristics."""
    dynamic_base: bool  # ASLR
    high_entropy_va: bool  # 64-bit ASLR
    nx_compat: bool  # DEP
    no_seh: bool
    guard_cf: bool  # Control Flow Guard
    wdm_driver: bool
    ts_aware: bool

    def summary(self) -> List[str]:
        flags = []
        if self.dynamic_base:
            flags.append("ASLR")
        if self.high_entropy_va:
            flags.append("HighEntropyVA")
        if self.nx_compat:
            flags.append("DEP/NX")
        if self.guard_cf:
            flags.append("CFG")
        if self.no_seh:
            flags.append("NoSEH")
        return flags


@dataclass
class AuthenticodeInfo:
    """Authenticode digital signature information."""
    is_signed: bool
    cert_offset: int = 0
    cert_size: int = 0
    revision: int = 0
    cert_type: int = 0
    authenticode_sha256: str = ""

    @property
    def revision_str(self) -> str:
        if self.revision == 0x0200:
            return "WIN_CERT_REVISION_2_0"
        if self.revision == 0x0100:
            return "WIN_CERT_REVISION_1_0"
        return f"0x{self.revision:04X}"

    @property
    def type_str(self) -> str:
        if self.cert_type == 0x0002:
            return "PKCS#7 SignedData"
        if self.cert_type == 0x0001:
            return "X.509"
        return f"0x{self.cert_type:04X}"


@dataclass(frozen=True)
class ExportSymbol:
    """Represents a single exported symbol in a PE file."""
    ordinal: int
    rva: int
    name: Optional[str] = None
    is_forwarded: bool = False
    forward_name: Optional[str] = None
    demangled_name: Optional[str] = None
    known_name: Optional[str] = None

    @property
    def is_ordinal_only(self) -> bool:
        """True if the function is exported only by ordinal without a string name."""
        return self.name is None

    @property
    def safe_name(self) -> str:
        """Identifier-safe function name."""
        if self.name:
            return self.name.replace("?", "_").replace("@", "_")
        return f"Ordinal_{self.ordinal}"

    def __str__(self) -> str:
        fwd_str = f" -> {self.forward_name}" if self.is_forwarded else ""
        name_str = self.name if self.name else "<ordinal-only>"
        demang_str = f" [{self.demangled_name}]" if self.demangled_name else ""
        return f"[@{self.ordinal}] {name_str}{demang_str} (RVA 0x{self.rva:08X}){fwd_str}"


@dataclass(frozen=True)
class ImportSymbol:
    """Represents a symbol imported by a PE binary."""
    name: Optional[str] = None
    ordinal: Optional[int] = None

    @property
    def is_by_ordinal(self) -> bool:
        return self.name is None


@dataclass
class ImportDescriptor:
    """Represents a DLL dependency and its imported symbols."""
    dll_name: str
    symbols: List[ImportSymbol] = field(default_factory=list)
    is_delay_loaded: bool = False


@dataclass
class SectionInfo:
    """Represents a PE section header and its entropy metrics."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def is_packed(self) -> bool:
        """Heuristic for packed/encrypted sections (Shannon entropy >= 7.0 and size >= 1KB)."""
        return self.entropy >= 7.0 and self.raw_data_size >= 1024


@dataclass
class ResourceItem:
    """Represents a resource tree leaf in the PE .rsrc directory."""
    type_id: int
    type_name: str
    resource_id: Union[int, str]
    lang_id: int
    rva: int
    size: int


@dataclass
class AntiAnalysisIndicator:
    """Represents a detected anti-analysis, anti-debug, or memory tampering heuristic."""
    category: str  # "Anti-Debug", "Memory-Tampering", "Process-Enumeration", "Timing-Evasion"
    api_name: str
    source_dll: str
    description: str


@dataclass
class RichEntry:
    """Single compiler/linker tool record from the decrypted PE Rich Header."""
    prod_id: int
    build_id: int
    count: int
    tool_name: str = ""


@dataclass
class RichHeaderInfo:
    """MSVC Rich Header telemetry extracted between DOS stub and NT header."""
    is_present: bool
    xor_key: int = 0
    checksum_valid: bool = False
    entries: List[RichEntry] = field(default_factory=list)


@dataclass
class RelocInfo:
    """Summary of PE base relocation directory (.reloc)."""
    is_present: bool
    total_relocs: int = 0
    blocks_count: int = 0
    type_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class PeExportInfo:
    """Complete summary of a PE binary's export directory."""
    filepath: str
    dll_name: str
    arch: PeArch
    timestamp: int
    ordinal_base: int
    symbols: List[ExportSymbol] = field(default_factory=list)
    sha256: str = ""
    mitigations: Optional[PeMitigations] = None
    tls_callbacks: List[int] = field(default_factory=list)
    sections: List[SectionInfo] = field(default_factory=list)
    authenticode: Optional[AuthenticodeInfo] = None
    resources: List[ResourceItem] = field(default_factory=list)
    manifest: Optional[str] = None
    anti_analysis: List[AntiAnalysisIndicator] = field(default_factory=list)
    rich_header: Optional[RichHeaderInfo] = None
    relocations: Optional[RelocInfo] = None

    @property
    def named_exports(self) -> List[ExportSymbol]:
        """Symbols with a defined ASCII name."""
        return [s for s in self.symbols if not s.is_ordinal_only]

    @property
    def ordinal_only_exports(self) -> List[ExportSymbol]:
        """Symbols exported strictly by ordinal."""
        return [s for s in self.symbols if s.is_ordinal_only]

    @property
    def forwarded_exports(self) -> List[ExportSymbol]:
        """Symbols that forward execution to another DLL."""
        return [s for s in self.symbols if s.is_forwarded]

    @property
    def total_count(self) -> int:
        return len(self.symbols)
