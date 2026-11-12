"""Build/package the module locally; never connects to or changes a device."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

BASE = Path(__file__).resolve().parent
PACKAGE = BASE / "package"
SOURCE = BASE / "src/dell_pen_bridge.c"
BINARY = PACKAGE / "bin/dell-pen-bridge"
CHECKSUM = PACKAGE / "bin/dell-pen-bridge.sha256"
DIST = BASE / "dist"
TEXT_SUFFIXES = {".sh", ".prop", ".md", ".c", ".sha256", ".txt"}
TEXT_NAMES = {"LICENSE"}
EXPECTED_FILES = {
    "action.sh", "bin/check.sh", "bin/control.sh", "bin/dell-pen-bridge",
    "bin/dell-pen-bridge.sha256", "customize.sh", "module.prop", "README.md",
    "service.sh", "skip_mount", "src/dell_pen_bridge.c", "uninstall.sh",
    "LICENSE", "THIRD_PARTY_NOTICES.md",
    "LICENSES/Zig-MIT.txt", "LICENSES/musl-COPYRIGHT.txt",
    "LICENSES/musl-SOURCE-NOTICES.txt",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8"))


def check_binary(data: bytes) -> None:
    if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a little-endian 64-bit ELF executable")
    if int.from_bytes(data[18:20], "little") != 183:
        raise ValueError("Expected an AArch64 executable")


def verify_recorded_binary() -> str:
    checksum = CHECKSUM.read_bytes()
    if not re.fullmatch(rb"[0-9a-f]{64}\n", checksum):
        raise ValueError("Recorded checksum must contain 64 lowercase hex characters and LF")
    data = BINARY.read_bytes()
    check_binary(data)
    digest = sha256(data)
    if checksum != (digest + "\n").encode("ascii"):
        raise ValueError("Prebuilt binary differs from its recorded checksum")
    return digest


def compile_binary(compiler: str | None) -> str:
    executable = compiler or os.environ.get("ZIG") or shutil.which("zig")
    if not executable:
        raise SystemExit("Zig was not found. Use --zig PATH, or --package-only to reuse the verified binary.")
    executable = str(Path(executable).expanduser()) if compiler else executable
    compiler_version = subprocess.check_output([executable, "version"], text=True).strip()
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(BASE / "build-cache")
    temporary = BINARY.with_name("dell-pen-bridge.build")
    try:
        subprocess.run([
            executable, "cc", "-target", "aarch64-linux-musl", "-static", "-O2",
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
            "-Wl,-z,relro,-z,now", str(SOURCE), "-o", str(temporary),
        ], check=True, env=env)
        data = temporary.read_bytes()
        check_binary(data)
        temporary.replace(BINARY)
        write_text(CHECKSUM, sha256(data) + "\n")
    finally:
        if temporary.exists():
            temporary.unlink()
    return compiler_version


def sync_distribution_text() -> None:
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        write_text(PACKAGE / name, (BASE / name).read_text(encoding="utf-8-sig"))
    for path in sorted((BASE / "LICENSES").glob("*.txt")):
        write_text(PACKAGE / "LICENSES" / path.name, path.read_text(encoding="utf-8-sig"))
    shutil.copyfile(SOURCE, PACKAGE / "src/dell_pen_bridge.c")


def make_archive(output: Path, native_digest: str) -> list[dict[str, object]]:
    actual = {p.relative_to(PACKAGE).as_posix() for p in PACKAGE.rglob("*") if p.is_file()}
    if actual != EXPECTED_FILES:
        raise ValueError(f"Unexpected package contents; missing={sorted(EXPECTED_FILES - actual)}, extra={sorted(actual - EXPECTED_FILES)}")
    manifest = []
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in sorted(EXPECTED_FILES):
            path = PACKAGE / relative
            data = path.read_bytes()
            if path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES:
                data.decode("utf-8")
                if b"\r" in data or data.startswith(b"\xef\xbb\xbf"):
                    raise ValueError(f"Text must use UTF-8 without BOM and LF: {relative}")
            executable = path.suffix == ".sh" or relative == "bin/dell-pen-bridge"
            mode = 0o100755 if executable else 0o100644
            entry = zipfile.ZipInfo(relative, (2026, 11, 11, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = mode << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data, compresslevel=9)
            manifest.append({"path": relative, "size": len(data), "mode": oct(mode), "sha256": sha256(data)})
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != EXPECTED_FILES:
            raise RuntimeError("Archive integrity or file allowlist validation failed")
        if sha256(archive.read("bin/dell-pen-bridge")) != native_digest:
            raise RuntimeError("Archived binary hash mismatch")
        if archive.read("bin/dell-pen-bridge.sha256") != (native_digest + "\n").encode("ascii"):
            raise RuntimeError("Archived checksum format/content mismatch")
        for record in manifest:
            entry = archive.getinfo(str(record["path"]))
            if oct(entry.external_attr >> 16) != record["mode"]:
                raise RuntimeError("Archived permissions mismatch")
            if sha256(archive.read(entry)) != record["sha256"]:
                raise RuntimeError("Archived file hash mismatch")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", metavar="PATH", help="Zig executable; otherwise ZIG environment variable or PATH")
    parser.add_argument("--package-only", action="store_true", help="Verify and reuse the recorded prebuilt binary; no compiler needed")
    args = parser.parse_args()
    if args.package_only and args.zig:
        parser.error("--zig and --package-only cannot be combined")
    properties = dict(line.split("=", 1) for line in (PACKAGE / "module.prop").read_text(encoding="utf-8").splitlines() if "=" in line)
    version = properties["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Unexpected module version")
    if args.package_only and SOURCE.read_bytes() != (PACKAGE / "src/dell_pen_bridge.c").read_bytes():
        raise ValueError("Source differs from the packaged source. Recompile before packaging a changed program.")
    compiler_version = None if args.package_only else compile_binary(args.zig)
    native_digest = verify_recorded_binary()
    sync_distribution_text()
    DIST.mkdir(exist_ok=True)
    output = DIST / f"Pen-Bridge-nabu-Root-v{version}.zip"
    try:
        files = make_archive(output, native_digest)
    except Exception:
        if output.exists():
            output.unlink()
        raise
    digest = sha256(output.read_bytes())
    report = {"artifact": output.name, "sha256": digest, "native_sha256": native_digest,
              "mode": "package-only" if args.package_only else "compile-and-package",
              "compiler_version": compiler_version, "files": files}
    write_text(DIST / "build-manifest.json", json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    write_text(output.with_name(output.name + ".sha256"), digest + "  " + output.name + "\n")
    print(json.dumps({key: report[key] for key in ("artifact", "sha256", "native_sha256", "mode")}, indent=2))


if __name__ == "__main__":
    main()
