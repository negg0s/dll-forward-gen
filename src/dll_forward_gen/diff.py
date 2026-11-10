"""Export table comparison and diff engine."""

from dataclasses import dataclass, field
from typing import List, Tuple

from .models import ExportSymbol, PeExportInfo


@dataclass
class ExportDiffResult:
    """Represents differences between two PE export tables."""
    dll1_name: str
    dll2_name: str
    added: List[ExportSymbol] = field(default_factory=list)
    removed: List[ExportSymbol] = field(default_factory=list)
    modified: List[Tuple[ExportSymbol, ExportSymbol]] = field(default_factory=list)
    identical: List[ExportSymbol] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def format_report(self, use_color: bool = True) -> str:
        c_rst = "\033[0m" if use_color else ""
        c_bld = "\033[1m" if use_color else ""
        c_cyn = "\033[36m" if use_color else ""
        c_grn = "\033[32m" if use_color else ""
        c_red = "\033[31m" if use_color else ""
        c_ylw = "\033[33m" if use_color else ""
        c_dim = "\033[90m" if use_color else ""

        lines = [
            "",
            f"{c_cyn}{'=' * 82}{c_rst}",
            f" {c_bld}EXPORT TABLE DIFF: {self.dll1_name} <-> {self.dll2_name}{c_rst}",
            f"{c_cyn}{'=' * 82}{c_rst}",
            f" Summary: {c_grn}+{len(self.added)} added{c_rst}, {c_red}-{len(self.removed)} removed{c_rst}, {c_ylw}~{len(self.modified)} modified{c_rst}, {c_dim}{len(self.identical)} identical{c_rst}",
            f"{c_cyn}{'-' * 82}{c_rst}",
        ]

        if not self.has_changes:
            lines.append(f"  {c_grn}Export tables are identical in both binaries.{c_rst}")
            lines.append(f"{c_cyn}{'=' * 82}{c_rst}")
            return "\n".join(lines)

        for sym in self.added:
            sym_name = sym.name if sym.name else f"<Ordinal_{sym.ordinal}>"
            fwd = f" -> {sym.forward_name}" if sym.is_forwarded else ""
            lines.append(f"  {c_grn}+ [ADDED]    @{sym.ordinal:<5} {sym_name}{fwd} (RVA 0x{sym.rva:08X}){c_rst}")

        for sym in self.removed:
            sym_name = sym.name if sym.name else f"<Ordinal_{sym.ordinal}>"
            lines.append(f"  {c_red}- [REMOVED]  @{sym.ordinal:<5} {sym_name} (RVA 0x{sym.rva:08X}){c_rst}")

        for old_s, new_s in self.modified:
            sym_name = old_s.name if old_s.name else f"<Ordinal_{old_s.ordinal}>"
            diff_notes = []
            if old_s.ordinal != new_s.ordinal:
                diff_notes.append(f"Ordinal: @{old_s.ordinal} -> @{new_s.ordinal}")
            if old_s.forward_name != new_s.forward_name:
                diff_notes.append(f"Forward: {old_s.forward_name} -> {new_s.forward_name}")
            if old_s.rva != new_s.rva:
                diff_notes.append(f"RVA: 0x{old_s.rva:08X} -> 0x{new_s.rva:08X}")
            detail_str = ", ".join(diff_notes)
            lines.append(f"  {c_ylw}~ [MODIFIED] {sym_name} ({detail_str}){c_rst}")

        lines.append(f"{c_cyn}{'=' * 82}{c_rst}")
        return "\n".join(lines)


def diff_export_tables(info1: PeExportInfo, info2: PeExportInfo) -> ExportDiffResult:
    """Compare two export tables and return structured diff result."""
    result = ExportDiffResult(
        dll1_name=info1.dll_name,
        dll2_name=info2.dll_name,
    )

    # Key function: prefer name if exists, else ordinal string
    def symbol_key(sym: ExportSymbol) -> str:
        if sym.name:
            return f"name:{sym.name}"
        return f"ordinal:{sym.ordinal}"

    map1 = {symbol_key(s): s for s in info1.symbols}
    map2 = {symbol_key(s): s for s in info2.symbols}

    all_keys = sorted(set(map1.keys()) | set(map2.keys()))

    for k in all_keys:
        s1 = map1.get(k)
        s2 = map2.get(k)

        if s1 is None and s2 is not None:
            result.added.append(s2)
        elif s2 is None and s1 is not None:
            result.removed.append(s1)
        elif s1 is not None and s2 is not None:
            # Check for modifications
            if (
                s1.ordinal != s2.ordinal
                or s1.is_forwarded != s2.is_forwarded
                or s1.forward_name != s2.forward_name
                or s1.rva != s2.rva
            ):
                result.modified.append((s1, s2))
            else:
                result.identical.append(s1)

    return result
