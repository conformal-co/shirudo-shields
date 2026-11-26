# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright (c) 2026 Conformal Shield Registry contributors
"""The upatch tree hosts follow with `shirudo bpm tree sync` (tools/publish).

One tree, id `shields`, at <namespace>/upatch-tree:stable. Every selector
carries the label shield.<package>=auto, which the installer writes to
/etc/shirudo/node.labels for the shields the user picked.

Each shield version is its own upatch, <upatch>-<version>: one name, one
payload, ever, so a delete never meets another payload under its name.

Per kernel line (a [[versions.lines]] entry), each release, in one atomic
move of `stable`:
  1. add the build each line should run: the newest published version on
     the lines it covers, else the older build already there;
  2. delete a build from each line it no longer serves, everywhere once it
     serves none, and every build of a withdrawn shield or version.
Adds come first, so a line's old build unloads only after the new one
loaded; adds are republished every release for hosts that changed line or
label since.

Selectors are signed into the package, so each operation is a package of
its own (per build: an add and a delete per line, one delete-everywhere),
kept at <namespace>/upatch-tree-packages for later releases. The appends
run in a staging registry answering under the endpoint's host name; the
result is copied to the target, `stable` last.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import ocilib as oci
import shieldlib as sl

TREE_REPOSITORY = "upatch-tree"
PACKAGES_REPOSITORY = "upatch-tree-packages"
TREE_TAG = "stable"
TREE_ID = "shields"
TREE_MEDIA = "application/vnd.shirudo.upatch.tree.v1+json"
PACKAGE_MEDIA = "application/vnd.shirudo.bpm.package.v1+gzip"
MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
EMPTY_CONFIG = b"{}"
LABEL_VALUE = "auto"
EVERYWHERE = ()
STAGING_IMAGE = "registry@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"

Line = tuple[str, ...]          # a kernel line: its sorted kernel_release_prefix values


class TreeError(RuntimeError):
    pass


def label_key(package: str) -> str:
    return f"shield.{package}"


def upatch_source(beefile: dict[str, Any]) -> str:
    upatches = beefile.get("upatches") or []
    if len(upatches) != 1:
        raise TreeError("the tree takes shields with exactly one [[upatches]] entry")
    return upatches[0]["source"]


def upatch_name(beefile: dict[str, Any]) -> str:
    """The name bpm build gives the shield's upatch: its source's basename."""
    name = Path(upatch_source(beefile)).name
    for suffix in (".bpf.c", ".c"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def build_name(upatch: str, version: str) -> str:
    return f"{upatch}-{version}"


def line_of(line: dict[str, Any]) -> Line:
    return tuple(sorted(line["kernel_release_prefix"]))


def line_tag(line: Line) -> str:
    return hashlib.sha256(",".join(line).encode()).hexdigest()[:12] if line else "all"


# ------------------------------------------------------------ selectors and Beefiles


def add_selector(shield: dict[str, Any], line: Line) -> dict[str, Any]:
    out: dict[str, Any] = {"kernel_release_prefix": list(line), "architecture": sorted(sl.architectures(shield)),
                           "labels": {label_key(shield["package"]): [LABEL_VALUE]}}
    if any(h.get("needs_bpf_lsm") for h in shield.get("hooks", [])):
        out["kconfig"] = {"CONFIG_BPF_LSM": ["y"]}
    return out


def delete_selector(shield: dict[str, Any], line: Line) -> dict[str, Any]:
    out: dict[str, Any] = {"labels": {label_key(shield["package"]): [LABEL_VALUE]}}
    if line:
        out["kernel_release_prefix"] = list(line)
    return out


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(json.dumps(v) for v in values) + "]"


def tree_table(name: str, sel: dict[str, Any]) -> str:
    out = ["[upatches.tree]", f"id = {json.dumps(name)}", "", "[upatches.tree.selector]"]
    for key in ("architecture", "kernel_release_prefix"):
        if key in sel:
            out.append(f"{key} = {_toml_list(sel[key])}")
    for table in ("kconfig", "labels"):
        if table in sel:
            out += ["", f"[upatches.tree.selector.{table}]"]
            out += [f"{json.dumps(k)} = {_toml_list(v)}" for k, v in sorted(sel[table].items())]
    return "\n".join(out) + "\n"


_HEADER = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(#.*)?$")


def rewrite_beefile(text: str, table: str, source: str, new_source: str) -> str:
    """The Beefile with the upatch's source renamed and its [upatches.tree*]
    tables replaced by table, where the old ones were or else right after the
    [[upatches]] entry and its sub-tables."""
    out: list[str] = []
    in_tree = in_upatch = placed = False
    renamed = 0
    for line in text.splitlines():
        m = _HEADER.match(line)
        if m:
            name = m.group(1).replace('"', "")
            if in_upatch and not name.startswith("upatches.") and not placed:
                out += ["", *table.rstrip("\n").splitlines(), ""]
                placed = True
            in_upatch = name == "upatches" or (in_upatch and name.startswith("upatches."))
            in_tree = name.startswith("upatches.tree")
            if in_tree:
                if not placed:
                    out += table.rstrip("\n").splitlines() + [""]
                    placed = True
                continue
        if in_tree:
            continue
        if in_upatch and re.fullmatch(rf'\s*source\s*=\s*"{re.escape(source)}"\s*', line):
            line = f'source = "{new_source}"'
            renamed += 1
        out.append(line)
    if not placed:
        out += ["", *table.rstrip("\n").splitlines()]
    if renamed != 1:
        raise TreeError(f"the Beefile names its upatch source {source!r} {renamed} times, not once")
    return "\n".join(out).rstrip("\n") + "\n"


def tree_sources(directory: Path, dest: Path, name: str, sel: dict[str, Any]) -> None:
    """The shield's sources at dest, built as upatch <name> with the selector sel."""
    shutil.copytree(directory, dest)
    beefile = dest / "Beefile"
    source = upatch_source(sl.load_toml(beefile))
    suffix = ".bpf.c" if source.endswith(".bpf.c") else Path(source).suffix
    new_source = str(Path(source).with_name(name + suffix))
    (dest / source).rename(dest / new_source)
    beefile.write_text(rewrite_beefile(beefile.read_text(encoding="utf-8"), tree_table(name, sel),
                                       source, new_source), encoding="utf-8")


# ------------------------------------------------------------ reading the tree


def _document(reg: oci.Registry, repo: str, ref: str) -> tuple[str, dict[str, Any]]:
    body, digest, _ = reg.get_manifest(repo, ref)
    layers = json.loads(body).get("layers") or []
    docs = [l for l in layers if l.get("mediaType") == TREE_MEDIA]
    if len(docs) != 1:
        raise TreeError(f"{repo}:{ref} is not a upatch tree publication")
    return digest, json.loads(reg.get_blob(repo, docs[0]["digest"], docs[0].get("size")))


@dataclass
class Tree:
    digest: str | None              # of the manifest `stable` names, None without a tree
    operations: list[dict[str, Any]]

    def live(self) -> set[tuple[str, Line]]:
        """(build, line) pairs an add put there and no delete took away."""
        out: set[tuple[str, Line]] = set()
        for op in self.operations:
            line = tuple(sorted((op.get("selector") or {}).get("kernel_release_prefix") or []))
            if op["op"] == "add":
                out.add((op["id"], line))
            elif line:
                out.discard((op["id"], line))
            else:
                out = {pair for pair in out if pair[0] != op["id"]}
        return out


def read_tree(reg: oci.Registry, repo: str) -> Tree:
    try:
        digest, doc = _document(reg, repo, TREE_TAG)
    except oci.NotFound:
        return Tree(None, [])
    if doc.get("tree_id") != TREE_ID:
        raise TreeError(f"{repo}:{TREE_TAG} is the tree {doc.get('tree_id')!r}, not {TREE_ID!r}")
    docs = [doc]
    while docs[0]["base"]["seq"] > 0:
        docs.insert(0, _document(reg, repo, docs[0]["base"]["segment_manifest_digest"])[1])
    ops = [op for d in docs for op in d["operations"]]
    if [op["seq"] for op in ops] != list(range(1, len(ops) + 1)):
        raise TreeError(f"{repo}: the operations are not numbered 1 to {len(ops)}")
    return Tree(digest, ops)


# ------------------------------------------------------------ the plan


@dataclass
class Build:
    package: str
    version: str
    name: str                       # <upatch>-<version>
    directory: Path | None          # the sources, for the version main builds
    shield: dict[str, Any]
    lines: list[Line] = field(default_factory=list)


@dataclass
class Op:
    op: str                         # add or delete
    build: Build
    line: Line                      # EVERYWHERE for a delete-everywhere

    @property
    def tag(self) -> str:
        return f"{self.build.name}-{self.op}-{line_tag(self.line)}"

    def describe(self) -> str:
        where = ",".join(self.line) if self.line else "everywhere"
        return f"{'+' if self.op == 'add' else '-'} tree {self.op} {self.build.name} ({where})"


def known_builds(shields: list[tuple[Path, dict[str, Any]]]) -> dict[str, Build]:
    """Every version of every shield as a tree build, by name."""
    out = {}
    for directory, shield in shields:
        upatch = upatch_name(sl.load_toml(directory / "Beefile"))
        newest = sl.current_version(shield)
        for version in shield["versions"]:
            name = build_name(upatch, version["version"])
            out[name] = Build(shield["package"], version["version"], name,
                              directory if version is newest else None, shield,
                              sorted({line_of(l) for l in version["lines"]}))
    return out


def wanted(shields: list[tuple[Path, dict[str, Any]]], builds: dict[str, Build],
           live: set[tuple[str, Line]]) -> set[tuple[str, Line]]:
    """(build, line) pairs the tree should hold after this release."""
    out: set[tuple[str, Line]] = set()
    for directory, shield in shields:
        current = sl.published_version(shield)
        if current is None:
            continue
        upatch = upatch_name(sl.load_toml(directory / "Beefile"))
        newest = builds[build_name(upatch, current["version"])]
        covered = set(newest.lines)
        out |= {(newest.name, line) for line in covered}
        for name, line in live:
            old = builds.get(name)
            if (old and old.package == shield["package"] and line not in covered
                    and not sl.withdrawn_reason(shield, _version(shield, old.version))):
                out.add((name, line))
                covered.add(line)
    return out


def _version(shield: dict[str, Any], version: str) -> dict[str, Any]:
    return next(v for v in shield["versions"] if v["version"] == version)


def plan(tree: Tree, shields: list[tuple[Path, dict[str, Any]]]) -> list[Op]:
    """Adds first, then deletes (see the module docstring)."""
    builds = known_builds(shields)
    live = tree.live()
    # A shield removed from main: its builds leave the tree, from the delete
    # packages kept when they were published.
    for name, _ in live:
        builds.setdefault(name, Build("", "", name, None, {}))
    want = wanted(shields, builds, live)
    ops = [Op("add", builds[name], line) for name, line in sorted(want)]
    serving = {name for name, _ in want}
    retired = sorted({name for name, _ in live if name not in serving})
    ops += [Op("delete", builds[name], EVERYWHERE) for name in retired]
    ops += [Op("delete", builds[name], line) for name, line in sorted(live - want) if name in serving]
    return ops


def current(tree: Tree, shields: list[tuple[Path, dict[str, Any]]]) -> bool:
    """Whether the tree holds exactly what it should (nothing to release)."""
    builds = known_builds(shields)
    live = tree.live()
    return live == wanted(shields, builds, live)


# ------------------------------------------------------------ registries


def copy(src: oci.Registry, src_repo: str, dst: oci.Registry, dst_repo: str,
         ref: str, tags: list[str]) -> str:
    body, digest, media = src.get_manifest(src_repo, ref)
    for desc in oci.manifest_blobs(body):
        if not dst.has_blob(dst_repo, desc["digest"]):
            dst.put_blob(dst_repo, src.get_blob(src_repo, desc["digest"], desc.get("size")), desc["digest"])
    dst.put_manifest(dst_repo, digest, body, media)
    for tag in tags:
        dst.put_manifest(dst_repo, tag, body, media)
    return digest


def segment_tags(reg: oci.Registry, repo: str) -> dict[str, str]:
    """segment-<k> -> digest, k from 1 up to the first one absent."""
    out = {}
    k = 1
    while True:
        try:
            out[f"segment-{k}"] = reg.get_manifest(repo, f"segment-{k}")[1]
        except oci.NotFound:
            return out
        k += 1


def put_package(reg: oci.Registry, repo: str, tag: str, data: bytes) -> str:
    """A .bee as a one-layer OCI artifact."""
    layer = oci.sha256_digest(data)
    config = oci.sha256_digest(EMPTY_CONFIG)
    reg.put_blob(repo, EMPTY_CONFIG, config)
    reg.put_blob(repo, data, layer)
    body = json.dumps({
        "schemaVersion": 2, "mediaType": MANIFEST_MEDIA, "artifactType": PACKAGE_MEDIA,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": config, "size": len(EMPTY_CONFIG)},
        "layers": [{"mediaType": PACKAGE_MEDIA, "digest": layer, "size": len(data)}],
    }, separators=(",", ":")).encode()
    return reg.put_manifest(repo, tag, body, MANIFEST_MEDIA)


def get_package(reg: oci.Registry, repo: str, tag: str) -> bytes | None:
    try:
        body, _, _ = reg.get_manifest(repo, tag)
    except oci.NotFound:
        return None
    layers = [l for l in json.loads(body).get("layers") or [] if l.get("mediaType") == PACKAGE_MEDIA]
    if len(layers) != 1:
        raise TreeError(f"{repo}:{tag} holds no package")
    return reg.get_blob(repo, layers[0]["digest"], layers[0].get("size"))


def parse_endpoint(endpoint: str) -> tuple[str, str]:
    """oci://host[:port]/repository -> (host[:port], repository)."""
    m = re.fullmatch(r"oci://([^/]+)/(.+)", endpoint)
    if not m:
        raise TreeError(f"--tree-endpoint {endpoint!r} is not oci://<host>/<repository>")
    return m.group(1), m.group(2).strip("/")


class TreeStaging:
    """A throw-away registry that answers as the endpoint's host, port 80 or its own."""

    def __init__(self, host: str) -> None:
        self.host = host
        self.port = int(host.rsplit(":", 1)[1]) if ":" in host else 80
        self.name = f"shirudo-publish-tree-{time.time_ns()}"
        self.hosts = Path(tempfile.mkdtemp(prefix="shirudo-tree-hosts.")) / "hosts"
        self.mapped = 0

    def __enter__(self) -> "TreeStaging":
        name = self.host.rsplit(":", 1)[0]
        self.hosts.write_text(f"127.0.0.1 localhost {name}\n", encoding="utf-8")
        subprocess.run(["docker", "run", "-d", "--rm", "--name", self.name,
                        "-e", f"REGISTRY_HTTP_ADDR=0.0.0.0:{self.port}",
                        "-p", f"127.0.0.1::{self.port}", STAGING_IMAGE],
                       check=True, stdout=subprocess.DEVNULL)
        port = subprocess.run(["docker", "port", self.name, f"{self.port}/tcp"], check=True,
                              text=True, stdout=subprocess.PIPE).stdout.split()[0]
        self.mapped = int(port.rsplit(":", 1)[1])
        reg = self.registry()
        for _ in range(60):
            try:
                reg._request("GET", f"{reg.base}/v2/", "")
                return self
            except oci.OciError:
                time.sleep(0.5)
        raise TreeError("tree staging registry did not start")

    def __exit__(self, *exc: object) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        shutil.rmtree(self.hosts.parent, ignore_errors=True)

    def registry(self) -> oci.Registry:
        return oci.Registry(f"127.0.0.1:{self.mapped}", plain_http=True)

    def container_args(self) -> list[str]:
        """What a container in the staging registry's network adds to its run."""
        return ["-v", f"{self.hosts}:/etc/hosts:ro", "-e", "BPM_OCI_SCHEME=http"]


BuildPackage = Callable[[Build, str, Line, Path], Path]
RunAppend = Callable[[TreeStaging, list[tuple[Path, str]]], None]


def packages(target: oci.Registry, ns: str, ops: list[Op], work: Path,
             build: BuildPackage, log: Callable[[str], None]) -> list[Path]:
    """The package of each operation: kept, or built from main and kept.

    A version main builds gets all its packages at once (an add and a delete
    per line, a delete everywhere), so that later releases find them."""
    repo = f"{ns}/{PACKAGES_REPOSITORY}"
    out = []
    for op in ops:
        path = work / f"{op.tag}.bee"
        data = get_package(target, repo, op.tag)
        if data is None:
            if op.build.directory is None:
                raise TreeError(f"{repo}:{op.tag} is missing and {op.build.name} is not a version main builds")
            for kind, line in ([("add", l) for l in op.build.lines] + [("delete", l) for l in op.build.lines]
                               + [("delete", EVERYWHERE)]):
                tag = Op(kind, op.build, line).tag
                if get_package(target, repo, tag) is None:
                    log(f"build and keep {repo}:{tag}")
                    put_package(target, repo, tag, build(op.build, kind, line, work).read_bytes())
            data = get_package(target, repo, op.tag)
        path.write_bytes(data)
        out.append(path)
    return out


def publish(target: oci.Registry, ns: str, endpoint: str, tree: Tree, ops: list[Op],
            bees: list[Path], run_append: RunAppend, expect: set[tuple[str, Line]],
            log: Callable[[str], None]) -> str:
    """Append the operations in staging and copy the result to target; the new
    stable manifest digest."""
    host, host_repo = parse_endpoint(endpoint)
    tree_repo = f"{ns}/{TREE_REPOSITORY}"
    with TreeStaging(host) as staging:
        sreg = staging.registry()
        if tree.digest:
            for op in tree.operations:
                copy(target, tree_repo, sreg, host_repo, op["artifact"]["manifest_digest"], [])
            for tag, digest in segment_tags(target, tree_repo).items():
                copy(target, tree_repo, sreg, host_repo, digest, [tag])
            copy(target, tree_repo, sreg, host_repo, tree.digest, [TREE_TAG])
        run_append(staging, [(path, op.op) for path, op in zip(bees, ops)])
        after = read_tree(sreg, host_repo)
        if after.live() != expect:
            raise TreeError(f"the staged tree holds {sorted(after.live())}, expected {sorted(expect)}")
        if tree.digest != read_tree(target, tree_repo).digest:
            raise TreeError("the live tree changed while publishing; run again")
        for op in after.operations[len(tree.operations):]:
            a = op["artifact"]
            tag = f"upatch-{op['id']}-{a['payload_sha256'].removeprefix('sha256:')[:16]}"
            # A load artifact and its unload directive may name one payload:
            # each keeps a tag of its own, so that neither is collected.
            copy(sreg, host_repo, target, tree_repo, a["manifest_digest"],
                 [tag if op["op"] == "add" else f"{tag}-unload"])
        known = segment_tags(target, tree_repo)
        for tag, digest in segment_tags(sreg, host_repo).items():
            if known.get(tag) != digest:
                copy(sreg, host_repo, target, tree_repo, digest, [tag])
        digest = copy(sreg, host_repo, target, tree_repo, after.digest, [TREE_TAG])
        log(f"{tree_repo}:{TREE_TAG} -> {digest}, generation "
            f"{_document(target, tree_repo, TREE_TAG)[1]['generation']}, {len(after.operations)} operations")
        return digest
