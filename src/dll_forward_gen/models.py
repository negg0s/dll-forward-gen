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
class ExportSymbol:
    """Represents a single exported symbol in a PE file."""
    ordinal: int
    rva: int
    name: Optional[str] = None
    is_forwarded: bool = False
    forward_name: Optional[str] = None

    @property
    def is_ordinal_only(self) -> bool:
        """True if the function is exported only by ordinal without a string name."""
        return self.name is None

    @property
    def safe_name(self) -> str:
        """Identifier-safe function name."""
        if self.name:
            # Replace characters illegal in C identifiers if needed
            return self.name.replace("?", "_").replace("@", "_")
        return f"Ordinal_{self.ordinal}"

    def __str__(self) -> str:
        fwd_str = f" -> {self.forward_name}" if self.is_forwarded else ""
        name_str = self.name if self.name else "<ordinal-only>"
        return f"[@{self.ordinal}] {name_str} (RVA 0x{self.rva:08X}){fwd_str}"


@dataclass
class PeExportInfo:
    """Complete summary of a PE binary's export directory."""
    filepath: str
    dll_name: str
    arch: PeArch
    timestamp: int
    ordinal_base: int
    symbols: List[ExportSymbol] = field(default_factory=list)

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
