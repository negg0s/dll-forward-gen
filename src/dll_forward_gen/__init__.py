"""dll-forward-gen: Zero-dependency PE export forwarder and C++ proxy generator."""

from .models import ExportSymbol, PeArch, PeExportInfo
from .pe_parser import PeParser, PeParseError
from .generator import CodeGenerator, GeneratorMode

__version__ = "0.1.0"
__all__ = [
    "ExportSymbol",
    "PeArch",
    "PeExportInfo",
    "PeParser",
    "PeParseError",
    "CodeGenerator",
    "GeneratorMode",
]
