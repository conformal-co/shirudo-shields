# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright (c) 2026 Conformal Shield Registry contributors
"""Helpers shared by the tools: loading shields, the registry JSON and the README table."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHIELDS = ROOT / "shields"
SCHEMA = ROOT / "schema" / "shield.schema.json"
DISTROS = ROOT / "schema" / "distros.json"
REGISTRY = ROOT / "catalog" / "shield-registry.json"
README = ROOT / "README.md"
SHIELD_DIR = re.compile(r"^(CVE-\d{4}-\d{4,})-([a-z0-9][a-z0-9-]*)$")
# Program sections the Shirudo stock-kernel port attaches.
ATTACH_EXACT = {"cgroup_skb/ingress", "cgroup_skb/egress", "netfilter"}
ATTACH_PREFIXES = ("lsm/", "lsm.s/", "fentry/", "fentry.s/", "fexit/", "fexit.s/", "tp_btf/",
                   "fmod_ret/", "fmod_ret.s/", "kprobe/", "kretprobe/", "xdp/")
# Sections of a shield's README.md, in this order.
README_SECTIONS = ["How it works", "What breaks", "Not covered", "Kernels", "Install", "References"]
TABLE_BEGIN = "<!-- shields:table:begin -->"
TABLE_END = "<!-- shields:table:end -->"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def shield_dirs() -> list[Path]:
    if not SHIELDS.is_dir():
        return []
    return sorted(p for p in SHIELDS.iterdir() if p.is_dir() and not p.name.startswith("."))


def load_shields() -> list[tuple[Path, dict[str, Any]]]:
    return [(d, load_toml(d / "shield.toml")) for d in shield_dirs() if (d / "shield.toml").is_file()]


def load_distros() -> dict[str, Any]:
    return json.loads(DISTROS.read_text(encoding="utf-8"))


def version_key(version: str) -> tuple[int, ...]:
    """'1.0.2' or '6.12' -> (1, 0, 2) or (6, 12)."""
    return tuple(int(part) for part in version.split("."))


def attach_supported(section: str) -> bool:
    section = section.removeprefix("?")
    return section in ATTACH_EXACT or any(
        section.startswith(prefix) and len(section) > len(prefix) for prefix in ATTACH_PREFIXES)


def withdrawn_reason(shield: dict[str, Any], version: dict[str, Any] | None = None) -> str | None:
    return shield.get("withdrawn") or (version or {}).get("withdrawn")


def current_version(shield: dict[str, Any]) -> dict[str, Any] | None:
    """The newest version: the one the sources in this tree build."""
    return max(shield["versions"], key=lambda v: version_key(v["version"]), default=None)


def published_version(shield: dict[str, Any]) -> dict[str, Any] | None:
    """What the index serves: the newest version, unless it or the shield is withdrawn."""
    current = current_version(shield)
    return None if current is None or withdrawn_reason(shield, current) else current


def architectures(shield: dict[str, Any]) -> list[str]:
    return list(shield.get("architectures") or ["x86_64"])


# ------------------------------------------------------------------ registry


def _affected_versions(shield: dict[str, Any], distro: str) -> str | None:
    """The affected kernel packages on one distro as a comparison, primary CVE first."""
    texts = []
    for cve in shield["cve_ids"]:
        for row in shield["affected"]["fixes"]:
            if row["distro"] != distro or row["cve"] != cve:
                continue
            if row["status"] == "fixed":
                text = "< " + " || < ".join(row["fixed"])
            elif row["status"] == "no-fix":
                text = "all (no fix released)"
            else:
                continue
            texts.append(text if len(shield["cve_ids"]) == 1 else f"{cve}: {text}")
    text = "; ".join(texts)
    return (text if len(text) <= 500 else text[:497] + "...") or None


def distro_fixes(shield: dict[str, Any], distros: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for row in shield["affected"]["fixes"]:
        distro = distros[row["distro"]]
        os_release = distro.get("os_release") or {}
        out.append({
            "distro": row["distro"],
            "name": distro["name"],
            "cve": row["cve"],
            "status": row["status"],
            "fixed": list(row.get("fixed") or []),
            "kernel_package": list(row.get("kernel_package") or distro.get("packages") or []),
            "compare": distro.get("compare"),
            "line_guard": bool(distro.get("line_guard", True)),
            "os_release_id": list(os_release.get("id") or []),
            "version_id": os_release.get("version_id"),
            "variant_id": os_release.get("variant_id"),
            "uname_regex": distro.get("uname_regex"),
            "uname_not_regex": distro.get("uname_not_regex"),
            "source": row.get("source"),
        })
    return out


def relevance(shield: dict[str, Any], upstream: dict[str, Any]) -> dict[str, Any] | None:
    rel = shield.get("relevance")
    if not rel:
        return None
    fixed = rel.get("upstream_fixed") or {}
    branches = sorted((k for k in fixed if k != "mainline"), key=version_key)
    out: dict[str, Any] = {
        "reachable": [{k: v for k, v in check.items() if k != "note"} for check in rel.get("reachable") or []],
        "fix_markers": list(rel.get("fix_markers") or []),
        "introduced": rel.get("introduced"),
        "upstream_fixed": [{"branch": b, "fixed": fixed[b]} for b in branches]
        + ([{"branch": "mainline", "fixed": fixed["mainline"]}] if "mainline" in fixed else []),
        "upstream_kernels": [],
    }
    if fixed or rel.get("introduced"):
        for key, entry in upstream.items():
            os_release = entry.get("os_release") or {}
            out["upstream_kernels"].append({
                "id": key,
                "name": entry["name"],
                "os_release_id": list(os_release.get("id") or []),
                "uname_regex": entry.get("uname_regex"),
                "uname_not_regex": entry.get("uname_not_regex"),
                "unpackaged": bool(entry.get("unpackaged", False)),
            })
    return out


def registry_package(directory: Path, shield: dict[str, Any]) -> dict[str, Any]:
    """One package of catalog/shield-registry.json.

    Per version, one target per kernel line and distro it is offered on
    (component = the distro, versions = its affected packages), or per line
    when the line names no distros (component = the line).
    """
    data = load_distros()
    distros = data["distros"]
    rel = directory.relative_to(ROOT).as_posix()
    binding = shield["hooks"][0]["binding"]
    detail = " + ".join(h["attach"] + ("; needs BPF LSM" if h["needs_bpf_lsm"] else "; no BPF LSM needed")
                        for h in shield["hooks"])[:2000]
    versions = []
    for version in shield["versions"]:
        targets = []
        for line in version["lines"]:
            for arch in architectures(shield):
                for distro in line.get("distros") or [None]:
                    name = distros[distro]["name"] if distro else line["name"][:500]
                    targets.append({
                        "product": "Linux kernel",
                        "component": name,
                        "versions": (_affected_versions(shield, distro) if distro else None) or line["name"][:500],
                        "architecture": arch,
                        "binding": binding,
                        "binding_detail": detail,
                        "kernel_line": line["name"][:500],
                        "kernel_release_prefix": list(line["kernel_release_prefix"]),
                    })
        reason = withdrawn_reason(shield, version)
        entry = {"version": version["version"], "status": "withdrawn" if reason else "published"}
        if reason:
            entry["reason"] = reason
        versions.append(entry | {"targets": targets})
    package = {
        "package": shield["package"],
        "display_name": shield.get("display_name"),
        "cve_ids": list(shield["cve_ids"]),
        "title": shield["title"],
        "kind": shield["kind"],
        "backend": shield["backend"],
        "source_path": rel,
        "versions": versions,
        "distro_fixes": distro_fixes(shield, distros),
    }
    relevance_ = relevance(shield, data.get("upstream_kernels") or {})
    if relevance_ is not None:
        package["relevance"] = relevance_
    return package


def render_registry() -> str:
    packages = sorted((registry_package(d, s) for d, s in load_shields() if s["versions"]),
                      key=lambda p: p["package"])
    return json.dumps({"schema": 1, "packages": packages}, indent=2, ensure_ascii=False) + "\n"


# ------------------------------------------------------------------ README table


def readme_table() -> str:
    rows = ["| Package | Bug | Hook | Version | Kernel lines | Status |", "|---|---|---|---|---|---|"]
    shields = sorted(load_shields(), key=lambda item: (published_version(item[1]) is None, item[1]["package"]))
    for directory, shield in shields:
        cves = ", ".join(shield["cve_ids"])
        bug = f"{shield['display_name']} ({cves})" if shield.get("display_name") else cves
        main = [h["attach"] for h in shield["hooks"] if not h["attach"].startswith(("fentry/", "fexit/"))]
        helpers = len(shield["hooks"]) - len(main)
        hook = ", ".join(f"`{a}`" for a in main) + (f" + {helpers} helper{'s' if helpers > 1 else ''}" if helpers else "")
        newest = current_version(shield)
        version = newest["version"] if newest else "none"
        lines = ", ".join(p for line in newest["lines"] for p in line["kernel_release_prefix"]) if newest else ""
        status = "published" if published_version(shield) else "withdrawn"
        rows.append(f"| [`{shield['package']}`](shields/{directory.name}/) | {bug} | {hook} | {version} | {lines} | {status} |")
    return "\n".join(rows)


def splice_readme(text: str, table: str) -> str:
    start = text.index(TABLE_BEGIN) + len(TABLE_BEGIN)
    return text[:start] + "\n" + table + "\n" + text[text.index(TABLE_END):]
