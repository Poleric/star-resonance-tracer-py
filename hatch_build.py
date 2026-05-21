import itertools
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

INIT_TEMPLATE = """
\"\"\"Generated protobuf modules for BPSR.\"\"\"
from __future__ import annotations
import sys
from pathlib import Path

_pkg_dir = Path(__file__).resolve().parent
_pkg_str = str(_pkg_dir)
if _pkg_str not in sys.path:
    sys.path.insert(0, _pkg_str)
    
__all__: list[str] = []
"""

PB_INIT_TEMPLATE = """
\"\"\"Generated chat protobuf modules.\"\"\"
"""

DEFAULT_BATCH_SIZE = 50


def build_protos(
        protos: Sequence[Path],
        includes: Sequence[Path],
        python_output: Path,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE
):
    for batch in itertools.batched(protos, batch_size):
        command = [
                      sys.executable,
                      "-m",
                      "grpc_tools.protoc",
                      f"--python_out={python_output}",
                      f"--pyi_out={python_output}",
                  ] + [
                      f"-I{include}" for include in includes
                  ] + [
                      f"{proto_file}" for proto_file in batch
                  ]

        proc = subprocess.run(command, check=True)
        if proc.returncode != 0:
            raise Exception(f"error {proc.returncode}: failed")


def build_package_protos(
        package_root: Path,
        includes: Sequence[Path],
        python_output: Path,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE
):
    build_protos(tuple(package_root.glob("*.proto")), includes, python_output, batch_size=batch_size)


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        star_data = Path(self.root) / "ref" / "StarResonanceData" / "proto"
        python_output = Path(self.root) / "src" / "star_resonance_tracer" / "proto"

        python_output.mkdir(exist_ok=True)
        (python_output / "__init__.py").write_text(INIT_TEMPLATE, encoding="utf-8")

        build_package_protos(star_data / "zproto", [star_data / "zproto"], python_output)
        # build_package_protos(star_data / "chat", [star_data / "chat"], python_output)
        # build_package_protos(star_data / "bokura", [star_data / "bokura", star_data], python_output)
        # build_package_protos(star_data / "table_config", [star_data / "table_config"], python_output)
        # build_protos([star_data / "table_basic.proto"], [star_data], python_output)

    def clean(self, versions: list[str]) -> None:
        python_protos = Path(self.root) / "src" / "star_resonance_tracer" / "proto"
        shutil.rmtree(python_protos)
