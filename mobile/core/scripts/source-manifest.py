#!/usr/bin/env python3
"""Record only the AAR's platform dependency sources and binding inputs."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess

parser = argparse.ArgumentParser()
phase = parser.add_mutually_exclusive_group(required=True)
phase.add_argument("--prepare", action="store_true")
phase.add_argument("--after-build", action="store_true")
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parents[3]
output = root / "mobile/core/build"
go_bin = os.environ.get("GO_BIN", os.environ.get("LOCKLARK_GO", "go"))
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
mobile_module = json.loads(subprocess.check_output([go_bin, "list", "-m", "-json", "golang.org/x/mobile"], cwd=root, text=True))
binding_tools = {key: mobile_module[key] for key in ("Version", "Sum", "GoModSum") if key in mobile_module}
for name in ("gobind", "gomobile"):
    executable = shutil.which(name)
    if executable is None: raise SystemExit("Binding tool missing from PATH: " + name)
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
