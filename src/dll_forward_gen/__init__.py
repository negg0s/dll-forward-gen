"""dll-forward-gen: Zero-dependency PE export forwarder and C++ proxy generator."""

__version__ = "0.3.0"

from .models import ExportSymbol, ImportDescriptor, ImportSymbol, PeArch, PeExportInfo, PeMitigations
from .pe_parser import PeParser, PeParseError
from .generator import CodeGenerator, GeneratorMode
from .diff import diff_export_tables, ExportDiffResult
from .batch import run_batch_config

__all__ = [
    "__version__",
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
    "run_batch_config",
]
