"""Batch proxy configuration parser and multi-DLL generator."""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from .generator import CodeGenerator, GeneratorMode
from .pe_parser import PeParser, resolve_dll_path


def run_batch_config(config_file: Union[str, Path]) -> List[Path]:
    """Execute batch generation from a JSON configuration file."""
    path = Path(config_file)
    if not path.is_file():
        raise FileNotFoundError(f"Batch config file not found: {config_file}")

    with open(path, "r", encoding="utf-8") as f:
        config: Dict[str, Any] = json.load(f)

    base_out_dir = Path(config.get("output_dir", "./proxies"))
    proxies_list = config.get("proxies", [])
    generated_dirs: List[Path] = []

    for item in proxies_list:
        dll_ref = item["dll"]
        resolved_path = resolve_dll_path(dll_ref)
        parser = PeParser.from_file(resolved_path)
        info = parser.parse()

        mode_str = item.get("mode", "pragma").lower()
        mode = GeneratorMode(mode_str)
        suffix = item.get("suffix")

        target_dll = item.get("target_dll")
        if suffix:
            stem = Path(info.dll_name).stem
            target_dll = f"{stem}{suffix}.dll"

        file_log = bool(item.get("file_log", False))
        hooked = item.get("hooks", [])

        custom_name = item.get("name")
        folder_name = custom_name if custom_name else f"{Path(info.dll_name).stem}_proxy"
        target_dir = base_out_dir / folder_name

        gen = CodeGenerator(
            info=info,
            mode=mode,
            target_dll=target_dll,
            enable_logging=bool(item.get("logging", True)),
            enable_file_log=file_log,
            hooked_symbols=hooked,
        )

        gen.emit_project(target_dir)
        generated_dirs.append(target_dir)

    return generated_dirs
