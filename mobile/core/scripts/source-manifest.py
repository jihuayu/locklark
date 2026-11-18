#!/usr/bin/env python3
"""Record only the AAR's platform dependency sources and binding inputs."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

# Expected binding tools. Their exact version and h1 hash are recorded here and
# checked independently against each tool's build info, because tools installed
# from go.mod tool directives may be built with a different go.sum line than
# tools installed at a fixed version.
MOBILE_VERSION = "v0.0.0-20260908204917-8b95e45f8d3e"
MOBILE_SUM = "h1:zYnHsDmxfxKH/x9DjYNAdoIdMsP8enB1Ncb10b3pdHk="

parser = argparse.ArgumentParser()
phase = parser.add_mutually_exclusive_group(required=True)
phase.add_argument("--prepare", action="store_true")
phase.add_argument("--after-build", action="store_true")
phase.add_argument("--check-tool-paths", action="store_true")
phase.add_argument("--check-tool-dir", action="store_true")
parser.add_argument("--tools-dir", type=pathlib.Path, required=True)
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[3]
output = root / "mobile/core/build"
try:
    if args.tools_dir.is_symlink():
        raise OSError()
    if not args.tools_dir.exists() and args.check_tool_dir:
        print("Binding tool directory has no unexpected entries")
        raise SystemExit(0)
    tools_dir = args.tools_dir.resolve(strict=True)
    if not tools_dir.is_dir():
        raise OSError()
    for entry in tools_dir.iterdir():
        if (entry.name not in ("gobind", "gomobile") or entry.is_symlink()
                or not entry.is_file() or not os.access(entry, os.X_OK)):
            raise SystemExit("Binding tool directory contains an unexpected entry")
except OSError:
    raise SystemExit("Binding tool directory unavailable")
if args.check_tool_dir:
    print("Binding tool directory has no unexpected entries")
    raise SystemExit(0)
go_bin = os.environ.get("GO_BIN", os.environ.get("LOCKLARK_GO", "go"))
selected_go = shutil.which("go")
try:
    explicit_go = shutil.which(go_bin)
    if explicit_go is None:
        raise OSError()
    explicit_go = pathlib.Path(explicit_go).resolve(strict=True)
    go_matches = (selected_go is not None and explicit_go.is_file()
                  and os.access(explicit_go, os.X_OK) and explicit_go.samefile(selected_go))
except OSError:
    go_matches = False
if not go_matches:
    raise SystemExit("Binding Go PATH mismatch")
go_bin = str(explicit_go)
installed_tools = {}
for name in ("gobind", "gomobile"):
    selected = shutil.which(name)
    try:
        executable = (tools_dir / name).resolve(strict=True)
        matches = (selected is not None and executable.is_file()
                   and os.access(executable, os.X_OK) and executable.samefile(selected))
    except OSError:
        matches = False
    if not matches:
        raise SystemExit("Binding tool PATH mismatch: " + name)
    installed_tools[name] = str(executable)
if args.check_tool_paths:
    print("Binding executable paths matched")
    raise SystemExit(0)
decoder = json.JSONDecoder()
file_fields = ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles",
               "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles", "EmbedFiles")
platform_sources, dependencies = {}, {}
for arch in ("arm64", "amd64"):
    env = dict(os.environ, GOOS="android", GOARCH=arch, CGO_ENABLED="1")
    raw = subprocess.check_output([go_bin, "list", "-deps", "-json", "./mobile/core"], cwd=root, env=env, text=True)
    selected = set()
    while raw.strip():
        package, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        module = package.get("Module", {})
        if module and not module.get("Main"):
            dependencies[module["Path"]] = {key: module[key] for key in ("Version", "Sum", "GoModSum") if key in module}
        if not module.get("Main"):
            continue
        directory = pathlib.Path(package["Dir"])
        for field in file_fields:
            for name in package.get(field, []):
                relative = str((directory / name).relative_to(root))
                selected.add(relative)
    platform_sources["android/" + arch] = sorted(selected)
compiled = set().union(*map(set, platform_sources.values()))
scripts = {"mobile/scripts/bind-android.sh", "mobile/core/scripts/bind-android.sh",
           "mobile/core/scripts/source-manifest.py"}
sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
           for name in sorted(compiled | scripts | {"go.mod", "go.sum"})}
artifact = output / "mobilecore.aar"
manifest_file = output / "source-manifest.json"
prepared_file = output / "source-manifest-before.json"
binding_tools = {"Version": MOBILE_VERSION, "Sum": MOBILE_SUM}
for name in ("gobind", "gomobile"):
    executable = installed_tools[name]
    tool_version = tool_sum = None
    for line in subprocess.check_output([go_bin, "version", "-m", executable], cwd=root, text=True).splitlines():
        fields = line.replace("\t", " ").split()
        if len(fields) >= 4 and fields[0] == "mod" and fields[1] == "golang.org/x/mobile":
            tool_version, tool_sum = fields[2], fields[3]
    if tool_version != MOBILE_VERSION or tool_sum != MOBILE_SUM:
        raise SystemExit("Binding tool " + name + " is " + str(tool_version) + " " + str(tool_sum)
                         + ", expected " + MOBILE_VERSION + " " + MOBILE_SUM)
    binding_tools[name + "_sha256"] = hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest()
manifest = {
    "source_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
    "sources": sources,
    "platform_sources": platform_sources,
    "build_scripts": sorted(scripts),
    "external_modules": dependencies,
    "binding_tools": binding_tools,
    "android_api": 30,
    "android_abis": ["arm64-v8a", "x86_64"],
}
output.mkdir(parents=True, exist_ok=True)
if args.prepare:
    prepared_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("Recorded exact native core inputs before binding")
    raise SystemExit(0)
previous = json.loads(prepared_file.read_text())
for key in ("sources", "platform_sources", "external_modules", "binding_tools"):
    if previous[key] != manifest[key]:
        raise SystemExit("Binding inputs changed during build: " + key + "; rerun binding")
manifest["verification"] = "exact transitive source, module and binding tool hashes matched before and after binding"
manifest["aar_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
manifest_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print("Recorded native core source manifest and AAR SHA-256")
