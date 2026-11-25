#!/usr/bin/env python3
"""Summarize a locked Cargo metadata graph; never approve licenses or a release."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 64 * 1024 * 1024
RESTRICTED = {"enterprise", "exchange", "dev_mode"}
NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
VERSION = re.compile(r"[0-9A-Za-z.+-]{1,128}\Z")


class InvalidInventory(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidInventory("INVALID_METADATA_GRAPH")


def index(items):
    require(isinstance(items, list))
    result = {}
    for item in items:
        require(isinstance(item, dict))
        key = item.get("id")
        require(isinstance(key, str) and key and key not in result)
        result[key] = item
    return result


def inventory(document):
    require(isinstance(document, dict))
    packages = index(document.get("packages"))
    resolve = document.get("resolve")
    require(isinstance(resolve, dict))
    nodes = index(resolve.get("nodes"))
    members = document.get("workspace_members")
    require(isinstance(members, list) and all(isinstance(x, str) for x in members))
    roots = [
        key for key in members
        if key in packages and packages[key].get("name") == "stalwart"
    ]
    require(len(roots) == 1)
    root = roots[0]
    visited = set()
    todo = [root]
    result = []
    while todo:
        key = todo.pop()
        if key in visited:
            continue
        require(key in packages and key in nodes)
        visited.add(key)
        package, node = packages[key], nodes[key]
        name, version = package.get("name"), package.get("version")
        require(isinstance(name, str) and NAME.fullmatch(name))
        require(isinstance(version, str) and VERSION.fullmatch(version))
        features = node.get("features")
        require(isinstance(features, list) and all(isinstance(x, str) for x in features))
        if RESTRICTED.intersection(features):
            raise InvalidInventory("RESTRICTED_FEATURE_PRESENT")
        if key == root:
            require({"postgres", "rocks"}.issubset(features))
        license_text = package.get("license")
        require(license_text is None or (
            isinstance(license_text, str) and len(license_text) <= 1024
            and all(32 <= ord(ch) < 127 for ch in license_text)
        ))
        source = package.get("source")
        require(source is None or isinstance(source, str))
        source_kind = (
            "path" if source is None else
            "registry" if source.startswith("registry+") else
            "git" if source.startswith("git+") else "other"
        )
        result.append({
            "name": name,
            "version": version,
            "license_expression": license_text or None,
            "license_file_present": bool(package.get("license_file")),
            "source_kind": source_kind,
        })
        deps = node.get("deps")
        require(isinstance(deps, list))
        for dep in deps:
            require(isinstance(dep, dict))
            target, kinds = dep.get("pkg"), dep.get("dep_kinds")
            require(isinstance(target, str) and target in packages and target in nodes)
            require(isinstance(kinds, list) and kinds)
            require(all(isinstance(k, dict) and "kind" in k
                        and k["kind"] in (None, "dev", "build") for k in kinds))
            # Exclude edges that are exclusively test/dev dependencies.
            if any(k["kind"] != "dev" for k in kinds):
                todo.append(target)
    result.sort(key=lambda x: (x["name"], x["version"], x["source_kind"],
                               x["license_expression"] or "", x["license_file_present"]))
    return {
        "schema_version": 1,
        "status": "INVENTORY_ONLY_REVIEW_REQUIRED",
        "package_count": len(result),
        "missing_license_expression_count": sum(
            p["license_expression"] is None for p in result
        ),
        "packages": result,
        "license_approved": False,
        "vulnerability_reviewed": False,
        "release_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    args = parser.parse_args()
    try:
        with args.metadata.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES)
        report = inventory(json.loads(raw))
        report["metadata_sha256"] = hashlib.sha256(raw).hexdigest()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except InvalidInventory as error:
        print("KMJ_DEPENDENCY_INVENTORY=" + str(error), file=sys.stderr)
    except (OSError, ValueError, UnicodeError, RecursionError, TypeError):
        print("KMJ_DEPENDENCY_INVENTORY=INVALID_INPUT", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
