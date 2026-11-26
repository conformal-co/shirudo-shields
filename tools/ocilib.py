# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# Copyright (c) 2026 Conformal Shield Registry contributors
"""A small OCI distribution client for tools/publish (Python standard library).

Reads and copies manifests and blobs by digest; nothing here signs or
verifies a signature. Authentication: HTTP Basic with the given user and
password on every request, and the registry token flow when the registry
answers 401 with a Bearer challenge. Blob downloads
follow redirects without the Authorization header.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

MANIFEST_MEDIA = "application/vnd.oci.image.manifest.v1+json"
INDEX_MEDIA = "application/vnd.oci.image.index.v1+json"
ACCEPT_MANIFEST = f"{MANIFEST_MEDIA}, {INDEX_MEDIA}"
MAX_MANIFEST = 4 << 20


class OciError(RuntimeError):
    pass


class NotFound(OciError):
    pass


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - urllib hook
        return None


@dataclass
class Registry:
    """One registry host, e.g. registry.example.com or 127.0.0.1:5000."""

    host: str
    plain_http: bool = False
    username: str | None = None
    password: str | None = None
    _bearer: dict[str, str] = field(default_factory=dict)

    @property
    def base(self) -> str:
        return f"{'http' if self.plain_http else 'https'}://{self.host}"

    # ------------------------------------------------------------ transport

    def _basic(self) -> str | None:
        if self.username is None:
            return None
        raw = f"{self.username}:{self.password or ''}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    def _token(self, challenge: str, scope_hint: str) -> str:
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = params.get("realm")
        if not realm:
            raise OciError(f"{self.host}: Bearer challenge without realm")
        query = {"service": params.get("service", "")}
        query["scope"] = params.get("scope") or scope_hint
        url = realm + "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(url)
        if self._basic():
            req.add_header("Authorization", self._basic())
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read())
        token = body.get("token") or body.get("access_token")
        if not token:
            raise OciError(f"{self.host}: token endpoint returned no token")
        return token

    def _request(self, method: str, url: str, repo: str, *, data: bytes | None = None,
                 headers: dict[str, str] | None = None, push: bool = False,
                 follow: bool = True) -> tuple[int, dict[str, str], bytes]:
        headers = dict(headers or {})
        scope = f"repository:{repo}:{'pull,push' if push else 'pull'}"
        opener = urllib.request.build_opener(_NoRedirect)
        for attempt in range(2):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            auth = self._bearer.get(scope) and f"Bearer {self._bearer[scope]}" or self._basic()
            if auth:
                req.add_header("Authorization", auth)
            try:
                with opener.open(req, timeout=300) as resp:
                    return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
            except urllib.error.HTTPError as err:
                hdrs = {k.lower(): v for k, v in err.headers.items()}
                body = err.read()
                if err.code in (301, 302, 303, 307, 308) and follow and "location" in hdrs:
                    target = urllib.parse.urljoin(url, hdrs["location"])
                    # A redirect to object storage: no registry credentials there.
                    with urllib.request.urlopen(urllib.request.Request(target, method=method), timeout=300) as resp:
                        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
                challenge = hdrs.get("www-authenticate", "")
                if err.code == 401 and attempt == 0 and challenge.lower().startswith("bearer"):
                    self._bearer[scope] = self._token(challenge[len("bearer"):].strip(), scope)
                    continue
                if err.code == 404:
                    raise NotFound(f"{method} {url}: 404") from None
                raise OciError(f"{method} {url}: HTTP {err.code} {body[:300]!r}") from None
            except (urllib.error.URLError, http.client.HTTPException, OSError) as err:
                raise OciError(f"{method} {url}: {err}") from None
        raise OciError(f"{method} {url}: unauthorized")

    def _url(self, repo: str, kind: str, ref: str) -> str:
        return f"{self.base}/v2/{repo}/{kind}/{ref}"

    # ------------------------------------------------------------ reading

    def get_manifest(self, repo: str, ref: str) -> tuple[bytes, str, str]:
        """(bytes, digest, media type); NotFound when the tag or digest is absent."""
        _, hdrs, body = self._request("GET", self._url(repo, "manifests", ref), repo,
                                      headers={"Accept": ACCEPT_MANIFEST})
        if len(body) > MAX_MANIFEST:
            raise OciError(f"{repo}:{ref}: manifest larger than {MAX_MANIFEST} bytes")
        digest = sha256_digest(body)
        if ref.startswith("sha256:") and ref != digest:
            raise OciError(f"{repo}@{ref}: the registry served other bytes ({digest})")
        media = json.loads(body).get("mediaType") or hdrs.get("content-type", MANIFEST_MEDIA)
        return body, digest, media

    def get_blob(self, repo: str, digest: str, size: int | None = None) -> bytes:
        _, _, body = self._request("GET", self._url(repo, "blobs", digest), repo)
        if sha256_digest(body) != digest or (size is not None and len(body) != size):
            raise OciError(f"{repo}@{digest}: blob digest or size mismatch")
        return body

    def has_blob(self, repo: str, digest: str) -> bool:
        try:
            self._request("HEAD", self._url(repo, "blobs", digest), repo, follow=False)
            return True
        except NotFound:
            return False
        except OciError as err:
            # A HEAD answered with a redirect to storage still means present.
            if "HTTP 30" in str(err):
                return True
            raise

    def referrers(self, repo: str, digest: str) -> list[dict[str, Any]]:
        try:
            _, _, body = self._request("GET", self._url(repo, "referrers", digest), repo,
                                       headers={"Accept": INDEX_MEDIA})
        except NotFound:
            return []
        return list(json.loads(body).get("manifests") or [])

    # ------------------------------------------------------------ writing

    def put_blob(self, repo: str, data: bytes, digest: str) -> None:
        if self.has_blob(repo, digest):
            return
        _, hdrs, _ = self._request("POST", f"{self.base}/v2/{repo}/blobs/uploads/", repo,
                                   data=b"", push=True)
        location = urllib.parse.urljoin(self.base + "/", hdrs.get("location", ""))
        sep = "&" if "?" in location else "?"
        self._request("PUT", f"{location}{sep}digest={urllib.parse.quote(digest)}", repo,
                      data=data, push=True,
                      headers={"Content-Type": "application/octet-stream"})

    def put_manifest(self, repo: str, ref: str, body: bytes, media: str) -> str:
        self._request("PUT", self._url(repo, "manifests", ref), repo, data=body, push=True,
                      headers={"Content-Type": media})
        return sha256_digest(body)


def manifest_blobs(body: bytes) -> list[dict[str, Any]]:
    doc = json.loads(body)
    out = [doc["config"]] if doc.get("config") else []
    out.extend(doc.get("layers") or [])
    return out


def copy_manifest(src: Registry, dst: Registry, repo: str, digest: str,
                  tags: list[str]) -> None:
    """Copy one image manifest, its blobs, then its tags (blobs first, tag last)."""
    body, real, media = src.get_manifest(repo, digest)
    if real != digest:
        raise OciError(f"{repo}@{digest}: source served {real}")
    for desc in manifest_blobs(body):
        dst.put_blob(repo, src.get_blob(repo, desc["digest"], desc.get("size")), desc["digest"])
    dst.put_manifest(repo, digest, body, media)
    for tag in tags:
        dst.put_manifest(repo, tag, body, media)
