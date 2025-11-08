# aeo_tool/sbom/sbom.py
import subprocess
import pathlib
from typing import Iterable, Optional, List

class SBOMGenerator:
    def __init__(self, workdir: str = "."):
        self.workdir = pathlib.Path(workdir)

    def _run(self, cmd: List[str], cwd: Optional[str] = None):
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)
        return proc

    def generate_from_path(self, target_path: str, output_path: str,
                           format: str = "cyclonedx", excludes: Optional[Iterable[str]] = None) -> str:
        """
        Generate SBOM using syft CLI.
        - target_path: e.g. '.', 'dir:/path', 'docker:image'
        - output_path: e.g. 'out/sbom-cyclonedx.json'
        - format: 'cyclonedx' | 'spdx' | 'json' (uses syft -o ...)
        - excludes: optional iterable of glob strings to pass as --exclude to syft (repeatable)
        Returns output_path on success or raises Exception on failure.
        Note: if syft doesn't accept --exclude and fails, we retry without excludes and emit a warning.
        """
        outp = pathlib.Path(output_path)
        outp.parent.mkdir(parents=True, exist_ok=True)

        # map format to syft output format
        # syft supports "cyclonedx-json" output name typically; we use a small mapping
        fmt_map = {
            "cyclonedx": "cyclonedx-json",
            "spdx": "spdx-json",
            "json": "json"
        }
        syft_out = fmt_map.get(format.lower(), "cyclonedx-json")

        base_cmd = ["syft", target_path, "-o", syft_out, "--file", str(outp)]

        # add excludes if provided
        cmd = list(base_cmd)
        if excludes:
            for e in excludes:
                cmd.extend(["--exclude", e])

        proc = self._run(cmd, cwd=str(self.workdir))
        if proc.returncode == 0:
            return str(outp)

        # If failed and we used excludes, try again without excludes (backwards-compatible)
        if excludes:
            # warn in stderr capture
            err = proc.stderr or proc.stdout or ""
            # retry without excludes
            retry_proc = self._run(base_cmd, cwd=str(self.workdir))
            if retry_proc.returncode == 0:
                # return with a warning (but still succeed)
                # write a tiny sidecar log so callers can inspect if needed
                try:
                    (outp.parent / "syft_excludes_warning.log").write_text(
                        "syft failed when using --exclude. Original stderr:\n" + err + "\n\nRetried without --exclude and succeeded."
                    )
                except Exception:
                    pass
                return str(outp)
            # both failed -> raise with combined output
            raise RuntimeError(f"syft failed (with excludes) stderr:\n{err}\n\n(retry without excludes stderr:\n{retry_proc.stderr or retry_proc.stdout})")
        else:
            raise RuntimeError(f"syft failed stderr:\n{proc.stderr or proc.stdout}")
