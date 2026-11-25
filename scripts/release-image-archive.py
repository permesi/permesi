#!/usr/bin/env python3
"""Pull published image digests into OCI archives the containment suite can load.

Flow: for each `service=ghcr.io/permesi/<service>@sha256:<digest>`, fetch that exact
manifest from the registry and check its bytes against the digest. A published release
image is an OCI index (the linux/amd64 image plus a build attestation), so resolve the
index to its linux/amd64 image manifest, then fetch that manifest, its config and every
layer, checking each blob against the digest that names it. Write the image as an OCI
layout archive whose single entry is named `localhost/permesi-candidate/<service>:<commit>`,
which is the name and shape the chart repository's loader already verifies and imports.

Why this shape: a node that pulls the published index digest runs exactly its
linux/amd64 manifest. Qualifying that manifest, reached through a digest-checked chain
from the published digest, qualifies the bytes that ship without depending on how a
cluster imports a multi-entry index. The platform manifest digests are printed so the
caller can require that the suite ran those and nothing else.

Nothing is trusted from the registry beyond what a digest pins. Only anonymous pulls of
the three public `ghcr.io/permesi` repositories are made.
"""

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.error
import urllib.request

REGISTRY = "ghcr.io"
SERVICES = ("permesi", "genesis", "web")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")
MAX_MANIFEST = 4 * 1024 * 1024
MAX_BLOB = 2 * 1024 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Blob downloads redirect to signed storage URLs that must not receive the token."""

    def redirect_request(self, *_args, **_kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Registry:
    """Anonymous, digest-addressed reads of one public repository."""

    def __init__(self, repository):
        self.repository = repository
        with OPENER.open(f"https://{REGISTRY}/token?scope=repository:{repository}:pull", timeout=30) as reply:
            self.token = json.load(reply)["token"]

    def _open(self, kind, digest, accept):
        request = urllib.request.Request(
            f"https://{REGISTRY}/v2/{self.repository}/{kind}/{digest}",
            headers={"Authorization": "Bearer " + self.token, "Accept": accept})
        try:
            return OPENER.open(request, timeout=120)
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location") if error.code in (301, 302, 303, 307, 308) else None
            if not location or not location.startswith("https://"):
                raise
            return OPENER.open(urllib.request.Request(location), timeout=120)

    def fetch(self, kind, digest, limit, accept="*/*"):
        """Return bytes that hash to `digest`, or fail; never more than `limit`."""
        if not DIGEST.fullmatch(digest):
            raise ValueError("malformed digest")
        with self._open(kind, digest, accept) as reply:
            data = reply.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"{kind} {digest} exceeds the size limit")
        if sha256(data) != digest:
            raise ValueError(f"{kind} {digest} does not match its digest")
        return data


def platform_manifest(index, operating_system="linux", architecture="amd64"):
    """Pick the one runnable image manifest of an index; attestations are not images."""
    matches = [entry for entry in index.get("manifests", [])
               if entry.get("platform", {}).get("os") == operating_system
               and entry.get("platform", {}).get("architecture") == architecture
               and entry.get("mediaType") in MANIFEST_TYPES]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {operating_system}/{architecture} image manifest, found {len(matches)}")
    digest = matches[0]["digest"]
    if not DIGEST.fullmatch(digest):
        raise ValueError("malformed platform manifest digest")
    return digest


def resolve(registry, published):
    """Follow the published digest to the image manifest that a linux/amd64 node runs."""
    accept = ", ".join(INDEX_TYPES + MANIFEST_TYPES)
    body = registry.fetch("manifests", published, MAX_MANIFEST, accept)
    document = json.loads(body)
    media_type = document.get("mediaType")
    if media_type in INDEX_TYPES or (media_type is None and "manifests" in document):
        digest = platform_manifest(document)
        body = registry.fetch("manifests", digest, MAX_MANIFEST, accept)
        document = json.loads(body)
        media_type = document.get("mediaType")
    else:
        digest = published
    if media_type not in MANIFEST_TYPES or "config" not in document or not document.get("layers"):
        raise ValueError("published digest does not lead to an image manifest")
    return digest, media_type, body, document


def write_archive(path, reference, digest, media_type, manifest_body, blobs):
    """Write an OCI layout whose only entry is the verified manifest under `reference`."""
    index = {"schemaVersion": 2, "manifests": [{
        "mediaType": media_type, "digest": digest, "size": len(manifest_body),
        "annotations": {"org.opencontainers.image.ref.name": reference}}]}
    members = {"oci-layout": json.dumps({"imageLayoutVersion": "1.0.0"}).encode(),
               "index.json": json.dumps(index).encode(),
               "blobs/sha256/" + digest.removeprefix("sha256:"): manifest_body}
    for blob_digest, data in blobs.items():
        members["blobs/sha256/" + blob_digest.removeprefix("sha256:")] = data
    with tarfile.open(path, "w") as archive:
        for name in sorted(members):
            info = tarfile.TarInfo(name)
            info.size = len(members[name])
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(members[name]))


def archive_image(service, published, app_sha, destination, registry=None):
    registry = registry or Registry(f"permesi/{service}")
    digest, media_type, body, manifest = resolve(registry, published)
    blobs = {}
    for descriptor in [manifest["config"], *manifest["layers"]]:
        blob_digest = descriptor["digest"]
        if blob_digest not in blobs:
            data = registry.fetch("blobs", blob_digest, MAX_BLOB)
            if len(data) != descriptor["size"]:
                raise ValueError(f"blob {blob_digest} has an unexpected size")
            blobs[blob_digest] = data
    reference = f"localhost/permesi-candidate/{service}:{app_sha}"
    write_archive(destination / f"{service}.tar", reference, digest, media_type, body, blobs)
    return digest


def parse_image(value):
    service, _, reference = value.partition("=")
    match = re.fullmatch(rf"{re.escape(REGISTRY)}/permesi/([a-z]+)@(sha256:[0-9a-f]{{64}})", reference)
    if service not in SERVICES or not match or match.group(1) != service:
        raise argparse.ArgumentTypeError(f"expected <service>={REGISTRY}/permesi/<service>@sha256:<digest>")
    return service, match.group(2)


def main():
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--app-sha", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--image", action="append", type=parse_image, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.app_sha):
        parser.error("--app-sha must be a full commit")
    images = dict(args.image)
    if sorted(images) != sorted(SERVICES) or len(args.image) != len(SERVICES):
        parser.error("provide exactly one --image for each of permesi, genesis and web")
    resolved = {}
    for service in SERVICES:
        resolved[service] = archive_image(service, images[service], args.app_sha, args.destination)
        print(f"{service}: published {images[service]} runs {resolved[service]}", file=sys.stderr)
    print("platform_digests=" + json.dumps(resolved, sort_keys=True))


if __name__ == "__main__":
    main()
