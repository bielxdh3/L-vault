"""Build the checked-in integrity crate into an E: scratch directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


DEFAULT_SOURCE_REVISION = "6ade1303d5ccf76e3ac9523932d40624ab722162"
PACKAGE_PATH = Path("native") / "integrity"
CRATE_NAME = "lvault-integrity"


class StagingError(Exception):
    pass


def _command(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)


def _git(repo: Path, *args: str) -> str:
    result = _command(["git", "-C", str(repo), *args])
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise StagingError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _host_target() -> str:
    rustc = shutil.which("rustc")
    if rustc is None:
        raise StagingError("rustc is not available on PATH")
    result = _command([rustc, "-vV"])
    if result.returncode:
        raise StagingError(f"rustc -vV failed: {result.stderr.strip()}")
    for line in result.stdout.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    raise StagingError("rustc -vV did not report a host target")


def _verify_source(repo: Path, requested_revision: str) -> tuple[str, str, str]:
    revision = _git(repo, "rev-parse", "--verify", f"{requested_revision}^{{commit}}")
    checkout_revision = _git(repo, "rev-parse", "HEAD")
    ancestor = _command(["git", "-C", str(repo), "merge-base", "--is-ancestor", revision, "HEAD"])
    if ancestor.returncode:
        raise StagingError("source revision must be an ancestor of the checkout HEAD")

    package = str(PACKAGE_PATH).replace("\\", "/")
    tracked_at_revision = _git(repo, "ls-tree", "-r", "--name-only", revision, "--", package).splitlines()
    tracked_now = _git(repo, "ls-files", "--", package).splitlines()
    untracked = _git(repo, "ls-files", "--others", "--exclude-standard", "--", package)
    ignored = _git(repo, "ls-files", "--others", "--ignored", "--exclude-standard", "--", package)
    changed = _command(["git", "-C", str(repo), "diff", "--quiet", revision, "--", package])
    if changed.returncode or untracked or ignored or sorted(tracked_at_revision) != sorted(tracked_now):
        raise StagingError("native/integrity differs from the requested source revision")

    tree = _git(repo, "rev-parse", f"{revision}:{package}")
    return revision, checkout_revision, tree


def _verify_windows_pe(path: Path, target: str) -> None:
    if "-windows-" not in target:
        raise StagingError("this local staging proof supports native Windows targets only")
    machine_by_arch = {"x86_64": 0x8664, "i686": 0x014C, "aarch64": 0xAA64}
    expected_machine = machine_by_arch.get(target.split("-", 1)[0])
    if expected_machine is None:
        raise StagingError(f"unsupported Windows target architecture: {target}")

    with path.open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise StagingError("Cargo output is not a Windows PE executable")
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        stream.seek(pe_offset)
        signature_and_machine = stream.read(6)
    if len(signature_and_machine) != 6 or signature_and_machine[:4] != b"PE\0\0":
        raise StagingError("Cargo output has an invalid PE header")
    machine = struct.unpack_from("<H", signature_and_machine, 4)[0]
    if machine != expected_machine:
        raise StagingError(f"PE architecture does not match target {target}")


def _scratch_root(path: Path, repo: Path) -> Path:
    if os.name != "nt":
        raise StagingError("the local staging proof requires Windows and an E: scratch drive")
    resolved = path.expanduser().resolve()
    if resolved.drive.upper() != "E:":
        raise StagingError("scratch root must be on E:")
    if resolved == repo or repo in resolved.parents:
        raise StagingError("scratch root must be outside the checkout")
    return resolved


def _cargo_registry_source(path: Path, repo: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.drive.upper() != "E:":
        raise StagingError("Cargo registry source must be on E:")
    if resolved.name.lower() != "registry" or not resolved.is_dir():
        raise StagingError("Cargo registry source must be an existing registry directory")
    if resolved == repo or repo in resolved.parents:
        raise StagingError("Cargo registry source must be outside the checkout")
    if any(item.is_symlink() for item in resolved.rglob("*")):
        raise StagingError("Cargo registry source must not contain symbolic links")
    return resolved


def build(args: argparse.Namespace) -> dict[str, str]:
    repo = args.repo_root.resolve()
    if not (repo / ".git").exists() and _command(["git", "-C", str(repo), "rev-parse", "--show-toplevel"]).returncode:
        raise StagingError(f"not a Git checkout: {repo}")

    scratch = _scratch_root(args.scratch_root, repo)
    revision, checkout_revision, source_tree = _verify_source(repo, args.source_revision)
    host = _host_target()
    if args.target != host:
        raise StagingError(f"requested target {args.target} does not match installed Rust host {host}")

    package_dir = repo / PACKAGE_PATH
    manifest_path = package_dir / "Cargo.toml"
    lock_path = package_dir / "Cargo.lock"
    if not manifest_path.is_file() or not lock_path.is_file():
        raise StagingError("native/integrity must contain Cargo.toml and Cargo.lock")
    manifest_sha256 = _sha256(manifest_path)
    lockfile_sha256 = _sha256(lock_path)

    cargo = shutil.which(args.cargo)
    if cargo is None:
        raise StagingError(f"Cargo executable not found: {args.cargo}")
    registry_source = (
        _cargo_registry_source(args.cargo_registry_source, repo)
        if args.cargo_registry_source is not None
        else None
    )
    scratch.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="lvault-integrity-", dir=scratch)).resolve()
    if run_dir == repo or repo in run_dir.parents:
        raise StagingError("staging output resolved inside the checkout")
    target_dir = run_dir / "cargo-target"
    cargo_home = run_dir / "cargo-home"
    temp_dir = run_dir / "temp"
    tmp_dir = run_dir / "tmp"
    cargo_home.mkdir()
    temp_dir.mkdir()
    tmp_dir.mkdir()
    if registry_source is not None:
        shutil.copytree(registry_source, cargo_home / "registry")
    command = [
        cargo,
        "build",
        "--release",
        "--locked",
        "--offline",
        "--target",
        args.target,
        "--manifest-path",
        str(manifest_path),
        "--target-dir",
        str(target_dir),
    ]
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("CARGO_")}
    environment.update(
        {
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(target_dir),
            "TEMP": str(temp_dir),
            "TMP": str(tmp_dir),
        }
    )
    result = subprocess.run(command, cwd=run_dir, env=environment, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise StagingError(f"offline locked Cargo build failed: {detail}")
    if _sha256(lock_path) != lockfile_sha256:
        raise StagingError("Cargo.lock changed during the build")

    artifact_name = f"{CRATE_NAME}.exe"
    built_artifact = target_dir / args.target / "release" / artifact_name
    if not built_artifact.is_file():
        raise StagingError(f"Cargo did not emit the expected executable: {built_artifact.name}")
    _verify_windows_pe(built_artifact, args.target)

    staged_dir = run_dir / "stage"
    staged_dir.mkdir()
    staged_artifact = staged_dir / artifact_name
    shutil.copyfile(built_artifact, staged_artifact)
    artifact_sha256 = _sha256(staged_artifact)
    if artifact_sha256 != _sha256(built_artifact):
        raise StagingError("staged executable checksum differs from Cargo output")
    _verify_windows_pe(staged_artifact, args.target)

    manifest = {
        "schema_version": 1,
        "evidence": "unsigned-local-build",
        "attestation": "Unsigned local evidence only; not a trusted release attestation.",
        "source_revision": revision,
        "checkout_revision": checkout_revision,
        "source_tree": source_tree,
        "crate": CRATE_NAME,
        "cargo_manifest_sha256": manifest_sha256,
        "lockfile_sha256": lockfile_sha256,
        "host": host,
        "target": args.target,
        "platform_format": "PE",
        "profile": "release",
        "build_flags": ["--locked", "--offline"],
        "artifact": artifact_name,
        "artifact_sha256": artifact_sha256,
    }
    provenance_path = run_dir / "provenance.json"
    provenance_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"manifest_path": str(provenance_path), "artifact_path": str(staged_artifact)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-revision", default=DEFAULT_SOURCE_REVISION)
    parser.add_argument("--target", required=True, help="must equal rustc's installed host target")
    parser.add_argument("--scratch-root", required=True, type=Path, help="new or existing E: scratch directory")
    parser.add_argument("--cargo", default="cargo", help="Cargo executable on PATH")
    parser.add_argument(
        "--cargo-registry-source",
        type=Path,
        help="optional existing E: registry directory to seed the isolated Cargo home",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(build(args), sort_keys=True))
    except (OSError, StagingError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
