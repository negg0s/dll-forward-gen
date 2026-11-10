"""Data models for PE exports and binary metadata."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


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
