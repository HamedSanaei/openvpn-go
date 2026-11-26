"""Check reviewed Go licenses and print a reproducible SPDX 2.3 inventory."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64"), ("darwin", "arm64"))
PACKAGES = ("./client", "./profile", "./transport", "./tunnel", "./cmd/ovpn-inspect", "./cmd/ovpn-xray")


def go(*args, **overrides):
    env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0", **overrides}
    return subprocess.check_output(["go", *args], cwd=ROOT, env=env, text=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def check_license(name, path, review):
    digest = sha256(path.read_bytes().replace(b"\r\n", b"\n"))
    if digest != review["sha256"]:
        raise ValueError(f"{name} license changed and requires review")


def build_list():
    template = "{{.Path}}|{{.Version}}|{{.Dir}}|{{if .Replace}}replacement{{end}}"
    rows = go("list", "-mod=readonly", "-m", "-f", template, "all").splitlines()
    modules = {}
    for row in rows:
        name, version, directory, replacement = row.split("|")
        if replacement:
            raise ValueError(f"{name} uses a module replacement")
        modules[name] = (version, directory)
    return modules


def linked_modules():
    template = "{{with .Module}}{{.Path}}{{end}}"
    paths = set()
    for system, arch in TARGETS:
        paths.update(go("list", "-mod=readonly", "-deps", "-f", template, *PACKAGES,
                        GOOS=system, GOARCH=arch).splitlines())
    paths.discard("")
    return paths


def package(name, spdx_id, license_id, location, version=None, purl=None):
    result = {
        "name": name,
        "SPDXID": spdx_id,
        "downloadLocation": location,
        "filesAnalyzed": False,
        "licenseConcluded": license_id,
        "licenseDeclared": license_id,
        "copyrightText": "NOASSERTION",
    }
    if version:
        result["versionInfo"] = version
    if purl:
        result["externalRefs"] = [{
            "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
            "referenceLocator": purl,
        }]
    return result


def make_sbom():
    review = json.loads((ROOT / "tools" / "release-audit.json").read_text(encoding="utf-8"))
    project = review["project"]
    stdlib = review["stdlib"]
    linked = review["linkedModules"]
    expected_paths = {project["path"], *linked}

    if go("env", "GOVERSION").strip() != stdlib["version"]:
        raise ValueError("the Go toolchain does not match the reviewed version")
    go("mod", "verify")
    if linked_modules() != expected_paths:
        raise ValueError("linked module inventory changed and requires review")
    modules = build_list()
    expected_versions = {project["path"]: "", **review["selectionOnly"],
                         **{path: pin["version"] for path, pin in linked.items()}}
    if {path: data[0] for path, data in modules.items()} != expected_versions:
        raise ValueError("selected module versions changed and require review")

    check_license(project["path"], ROOT / "LICENSE", project)
    check_license("Go", Path(go("env", "GOROOT").strip()) / "LICENSE", stdlib)
    packages = [
        package(project["path"], "SPDXRef-Project", project["license"], "NOASSERTION"),
        package("Go standard library and runtime", "SPDXRef-Go", stdlib["license"],
                f"https://go.dev/dl/#{stdlib['version']}", stdlib["version"]),
    ]
    for name, pin in sorted(linked.items()):
        version, directory = modules[name]
        check_license(name, Path(directory) / "LICENSE", pin)
        short = name.rsplit("/", 1)[1]
        packages.append(package(name, f"SPDXRef-Go-{short}", pin["license"],
                                f"https://proxy.golang.org/{name}/@v/{version}.zip",
                                version, f"pkg:golang/{name}@{version}"))

    identity = sha256(json.dumps(review, sort_keys=True).encode())
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "OpenVPN Go runtime dependency inventory",
        "documentNamespace": f"https://github.com/hamedsanaei/openvpn-go/sbom/{identity}",
        "creationInfo": {"created": review["created"], "creators": ["Tool: openvpn-go release-audit"]},
        "packages": packages,
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
             "relatedSpdxElement": "SPDXRef-Project"},
            *({"spdxElementId": "SPDXRef-Project", "relationshipType": "DEPENDS_ON",
               "relatedSpdxElement": dep} for dep in ("SPDXRef-Go", "SPDXRef-Go-crypto", "SPDXRef-Go-sys")),
            {"spdxElementId": "SPDXRef-Go-crypto", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-Go-sys"},
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="verify an existing SPDX document")
    args = parser.parse_args()
    try:
        document = json.dumps(make_sbom(), indent=2) + "\n"
        if args.check:
            if args.check.read_text(encoding="utf-8") != document:
                raise ValueError("the SPDX inventory differs from the reviewed dependencies")
            print("Reviewed dependency licenses and SPDX inventory verified")
        else:
            sys.stdout.write(document)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
