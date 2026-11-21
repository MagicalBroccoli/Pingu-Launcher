#!/usr/bin/env python3
"""Builds and VM-validates the pingu kernel modules for Valve's SteamOS kernels.

SteamOS has a read-only root and neither DKMS nor a compiler, so the modules are built
here against the exact linux-neptune packages Valve ships. `make launcher-dist` embeds them
into the launcher, which installs them on the device. Every kernel build gets its own
directory below the output, named by its build ID: Valve's channels (jupiter-3.9, jupiter-3.10, jupiter-main, ...) ship differently built
kernels under the same release string, and the module only accepts its own build.

The packages come from the pacman repository database of the mirror, which names the
current version and the SHA-256 of each file. The package signatures are not checked.
"""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIRROR = "https://steamdeck-packages.steamos.cloud/archlinux-mirror"
# Kernels before 6.6 are refused by the module build.
DEFAULT_SERIES = ("68", "611", "615", "616", "618", "72", "73")
# Stable (jupiter-3.9), then beta (jupiter-3.10), then the development one.
DEFAULT_REPOS = ("jupiter-3.9", "jupiter-3.10", "jupiter-main")
POLICY_FILES = (
    "Makefile",
    "dkms.conf",
    "probe.c",
    "policy.c",
    "policy.h",
    "trampoline.S",
    "umip.c",
    "cpuid_fault.c",
    "svm_capture_context.S",
    "svm_run_vm.S",
    "inc/host_state.h",
    "inc/vmcb_layout.h",
)


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def source_digest() -> str:
    """Identifies the module sources and the VM fixtures a build used."""
    files = [ROOT / "pingu-policy" / name for name in POLICY_FILES]
    files.append(ROOT / "pingu-policy/validation/manifest.json")
    files.append(ROOT / "pingu-policy/validation/pingu-module-tool")
    files.append(Path(__file__).resolve())
    digest = hashlib.sha256()
    for path in files:
        if path.exists():
            digest.update(
                str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes()
            )
    return digest.hexdigest()


def download(url: str, destination: Path, checksum: str) -> None:
    if destination.exists() and sha256(destination) == checksum:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    print(f"downloading {url}", flush=True)
    with (
        urllib.request.urlopen(url, timeout=120) as response,
        partial.open("wb") as sink,
    ):
        shutil.copyfileobj(response, sink)
    if sha256(partial) != checksum:
        partial.unlink()
        raise ValueError(f"checksum mismatch for {url}")
    partial.rename(destination)


def read_database(repo: str, cache: Path) -> dict[str, dict[str, str]]:
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / f"{repo}.db"
    url = f"{MIRROR}/{repo}/os/x86_64/{repo}.db"
    with urllib.request.urlopen(url, timeout=120) as response:
        path.write_bytes(response.read())
    packages: dict[str, dict[str, str]] = {}
    with tarfile.open(path) as database:
        for member in database.getmembers():
            if not member.name.endswith("/desc"):
                continue
            text = database.extractfile(member).read().decode()
            fields = {}
            for block in text.split("\n\n"):
                key, _, value = block.strip().partition("\n")
                fields[key.strip("%")] = value
            packages[fields["NAME"]] = fields
    return packages


def run(command: list[str], log: Path, **options) -> None:
    with log.open("ab") as sink:
        sink.write(("$ " + " ".join(map(str, command)) + "\n").encode())
        sink.flush()
        subprocess.run(
            command, stdout=sink, stderr=subprocess.STDOUT, check=True, **options
        )


def build_module(
    sources: Path, headers: Path, llvm: list[str], jobs: int, log: Path
) -> Path:
    """Compiles the module in `sources` and returns the one .ko that appeared."""
    run(
        [
            "make",
            "-C",
            str(headers),
            f"M={sources}",
            f"XCR0_HEADERS={headers}",
            # Keeps the build directories out of __FILE__ strings in the shipped module.
            f"KCFLAGS=-ffile-prefix-map={sources}=/src -ffile-prefix-map={headers}=/kernel",
            *llvm,
            f"-j{jobs}",
            "modules",
        ],
        log,
    )
    (module,) = sources.glob("*.ko")
    # The distribution's own modules are stripped the same way; BTF stays.
    run(["strip", "--strip-debug", str(module)], log)
    return module


def kernel_build_id(vmlinux: Path) -> str:
    """The GNU build ID of a little-endian ELF64 file, read from its note sections."""
    with vmlinux.open("rb") as source:
        header = source.read(64)
        if header[:4] != b"\x7fELF" or header[4] != 2:
            raise ValueError(f"{vmlinux} is not a 64-bit ELF file")
        (shoff,) = struct.unpack_from("<Q", header, 0x28)
        shentsize, shnum = struct.unpack_from("<HH", header, 0x3A)
        for index in range(shnum):
            source.seek(shoff + index * shentsize)
            section = source.read(shentsize)
            (sh_type,) = struct.unpack_from("<I", section, 4)
            offset, size = struct.unpack_from("<QQ", section, 0x18)
            if sh_type != 7:  # SHT_NOTE
                continue
            source.seek(offset)
            notes = source.read(size)
            at = 0
            while at + 12 <= len(notes):
                namesz, descsz, kind = struct.unpack_from("<III", notes, at)
                name_at = at + 12
                desc_at = name_at + (namesz + 3) // 4 * 4
                if kind == 3 and notes[name_at : name_at + namesz] == b"GNU\0":
                    return notes[desc_at : desc_at + descsz].hex()
                at = desc_at + (descsz + 3) // 4 * 4
    raise ValueError(f"{vmlinux} has no build ID")


def build_series(
    repo: str, series: str, packages: dict, arguments: argparse.Namespace
) -> str:
    kernel = packages[f"linux-neptune-{series}"]
    headers_package = packages[f"linux-neptune-{series}-headers"]
    if kernel["VERSION"] != headers_package["VERSION"]:
        raise ValueError("kernel and header packages are at different versions")
    base = arguments.work / repo / f"{series}-{kernel['VERSION']}"
    for package in (kernel, headers_package):
        archive = arguments.cache / repo / package["FILENAME"]
        download(
            f"{MIRROR}/{repo}/os/x86_64/{package['FILENAME']}",
            archive,
            package["SHA256SUM"],
        )
        marker = base / f".extracted-{package['NAME']}"
        if not marker.exists():
            base.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["tar", "--zstd", "-xf", str(archive), "-C", str(base)], check=True
            )
            marker.touch()
    (headers,) = base.glob("usr/lib/modules/*/build")
    release = (headers / "include/config/kernel.release").read_text().strip()
    identity = kernel_build_id(headers / "vmlinux")
    label = f"{release} [{identity}] ({repo})"
    destination = arguments.out / "releases" / identity
    digest = source_digest()
    recorded = destination / "source.json"
    if (
        not arguments.force
        and recorded.exists()
        and json.loads(recorded.read_text()).get("module_sources") == digest
        and ((destination / "validation.result.json").exists() or arguments.skip_vm)
    ):
        return f"{label}: already built"

    log = base / "build.log"
    log.unlink(missing_ok=True)
    config = (headers / ".config").read_text().splitlines()
    llvm = ["LLVM=1"] if "CONFIG_CC_IS_CLANG=y" in config else []

    policy = base / "pingu-policy"
    shutil.rmtree(policy, ignore_errors=True)
    policy.mkdir()
    for name in POLICY_FILES:
        (policy / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "pingu-policy" / name, policy / name)
    shutil.copytree(ROOT / "pingu-policy" / "validation", policy / "validation")
    policy_module = build_module(policy, headers, llvm, arguments.jobs, log)
    if not arguments.skip_vm:
        run(
            [
                str(policy / "validation" / "pingu-module-tool"),
                "validate",
                "--package",
                str(policy),
                "--headers",
                str(headers),
                "--kernel-release",
                release,
            ],
            log,
        )

    shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)
    shutil.copy2(policy_module, destination / policy_module.name)
    receipt = policy / "validation.result.json"
    if receipt.exists():
        shutil.copy2(receipt, destination / receipt.name)
    (destination / "SHA256SUMS").write_text(
        f"{sha256(destination / policy_module.name)}  {policy_module.name}\n"
    )
    (destination / "source.json").write_text(
        json.dumps(
            {
                "release": release,
                "build_id": identity,
                "repository": repo,
                "kernel_package": kernel["FILENAME"],
                "kernel_sha256": kernel["SHA256SUM"],
                "headers_package": headers_package["FILENAME"],
                "headers_sha256": headers_package["SHA256SUM"],
                "module_sources": digest,
                "vm_validated": not arguments.skip_vm,
            },
            indent=2,
        )
        + "\n"
    )
    return f"{label}: built" + ("" if not arguments.skip_vm else " (VM gate skipped)")


def list_builds(arguments: argparse.Namespace) -> list[dict[str, str]]:
    """One entry per distinct kernel build, for a CI job matrix."""
    seen = set()
    builds = []
    for repo in arguments.repo:
        packages = read_database(repo, arguments.cache / repo)
        for series in arguments.series:
            kernel = packages.get(f"linux-neptune-{series}")
            headers = packages.get(f"linux-neptune-{series}-headers")
            if kernel is None or headers is None:
                continue
            key = (kernel["SHA256SUM"], headers["SHA256SUM"])
            if key not in seen:
                seen.add(key)
                builds.append(
                    {"repo": repo, "series": series, "version": kernel["VERSION"]}
                )
    return builds


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--series",
        nargs="+",
        default=list(DEFAULT_SERIES),
        help="linux-neptune series, e.g. 618 72 73",
    )
    parser.add_argument(
        "--repo",
        nargs="+",
        default=list(DEFAULT_REPOS),
        help="mirror repositories (channels); the same release string can be a different build in each",
    )
    parser.add_argument("--out", type=Path, default=ROOT / "build" / "steamos")
    parser.add_argument("--work", type=Path, default=ROOT / ".work" / "steamos")
    parser.add_argument(
        "--cache", type=Path, help="package download cache (default: <work>/packages)"
    )
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the distinct kernel builds as a JSON job matrix and exit",
    )
    parser.add_argument(
        "--force", action="store_true", help="rebuild releases that are up to date"
    )
    parser.add_argument(
        "--skip-vm",
        action="store_true",
        help="build without the VM gate (CI does; `make steamos-modules` validates before a release)",
    )
    arguments = parser.parse_args()
    arguments.cache = arguments.cache or arguments.work / "packages"
    if arguments.list:
        print(json.dumps({"include": list_builds(arguments)}))
        return 0
    if (
        not (ROOT / "pingu-policy/validation/manifest.json").exists()
        and not arguments.skip_vm
    ):
        print("run `make module-validation-assets` first", file=sys.stderr)
        return 1
    failed = 0
    for repo in arguments.repo:
        packages = read_database(repo, arguments.cache / repo)
        for series in arguments.series:
            if f"linux-neptune-{series}" not in packages:
                continue
            try:
                print(build_series(repo, series, packages, arguments), flush=True)
            except (
                KeyError,
                ValueError,
                OSError,
                subprocess.CalledProcessError,
            ) as error:
                failed += 1
                print(
                    f"{repo} series {series}: FAILED ({error!r}); see {arguments.work}/{repo}/{series}-*/build.log",
                    file=sys.stderr,
                )
                for log in sorted(
                    (arguments.work / repo).glob(f"{series}-*/build.log")
                ):
                    lines = log.read_text(errors="replace").splitlines()
                    # The VM test prints every failed check once, far above the end of the log.
                    print(f"--- failed checks and errors in {log}", file=sys.stderr)
                    print(
                        "\n".join(
                            line
                            for line in lines
                            if "FAIL" in line or "error:" in line or "Error " in line
                        )[:4000],
                        file=sys.stderr,
                    )
                    print(f"--- end of {log}", file=sys.stderr)
                    print("\n".join(lines[-40:]), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
