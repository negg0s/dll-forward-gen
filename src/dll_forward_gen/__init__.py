"""dll-forward-gen: Zero-dependency PE export forwarder and C++ proxy generator."""

from .models import ExportSymbol, ImportDescriptor, ImportSymbol, PeArch, PeExportInfo, PeMitigations
from .pe_parser import PeParser, PeParseError
from .generator import CodeGenerator, GeneratorMode
from .diff import diff_export_tables, ExportDiffResult

__version__ = "0.2.0"
__all__ = [
    "ExportSymbol",
    "ImportSymbol",
    "ImportDescriptor",
    "PeArch",
    "PeExportInfo",
    "PeMitigations",
    "PeParser",
    "PeParseError",
    "CodeGenerator",
    "GeneratorMode",
    "diff_export_tables",
    "ExportDiffResult",
]
