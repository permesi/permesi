#!/usr/bin/env python3
"""Pull published image digests into OCI archives the containment suite can load.

Flow: for each `service=ghcr.io/permesi/<service>@sha256:<digest>`, fetch that exact
manifest from the registry and check its bytes against the digest. A published release
image is an OCI index (the linux/amd64 image plus a build attestation), so resolve the
index to its linux/amd64 image manifest, then fetch that manifest, its config and every
layer, checking each blob against the digest and size that name it. Write the image as
an OCI layout archive whose single entry is named
`localhost/permesi-candidate/<service>:<commit>`, which is the name and shape the chart
repository's loader already verifies and imports.

Why this shape: a linux/amd64 node that pulls the published index digest runs exactly
that image manifest. Qualifying it, reached through a digest-checked chain from the
published digest, qualifies the bytes that ship without depending on how a cluster
imports a multi-entry index. The platform manifest digests are printed so the caller
can require that the suite ran those and nothing else.

What this refuses: an index that carries any runnable image other than one linux/amd64
manifest. Publishing another platform would ship an image this qualification never
ran, so the release must stop until the qualification covers it. Every other entry of
the index (the build attestation) is fetched and digest-checked too, so a broken index
fails here and not later, when the release copies it to its version tags.

Nothing is trusted from the registry beyond what a digest pins. Only anonymous pulls of
the three public `ghcr.io/permesi` repositories are made.
"""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

REGISTRY = "ghcr.io"
SERVICES = ("permesi", "genesis", "web")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")
ACCEPT = ", ".join(INDEX_TYPES + MANIFEST_TYPES)
MAX_TOKEN = 64 * 1024
MAX_MANIFEST = 4 * 1024 * 1024
MAX_BLOB = 512 * 1024 * 1024
MAX_REDIRECTS = 3
ATTEMPTS = 3
REDIRECTS = (301, 302, 303, 307, 308)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are followed by hand so the bearer token never leaves the registry."""

    def redirect_request(self, *_args, **_kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def checked(kind, digest, data, limit):
    """The single place a fetched object is accepted: within `limit` and hashing to `digest`."""
    if not DIGEST.fullmatch(digest):
        raise ValueError("malformed digest")
    if len(data) > limit:
        raise ValueError(f"{kind} {digest} exceeds the size limit")
    if sha256(data) != digest:
        raise ValueError(f"{kind} {digest} does not match its digest")
    return data


class Registry:
    """Anonymous, digest-addressed reads of one public repository."""

    def __init__(self, repository, token=None, opener=OPENER):
        self.repository, self.opener = repository, opener
        self.token = token or json.loads(self._read(
            f"https://{REGISTRY}/token?scope=repository:{repository}:pull", {}, MAX_TOKEN))["token"]

    def _read(self, url, headers, limit):
        """GET at most `limit` + 1 bytes over HTTPS, following a few redirects without credentials."""
        for hop in range(MAX_REDIRECTS + 1):
            target = urllib.parse.urlsplit(url)
            if target.scheme != "https" or not target.hostname:
                raise ValueError("registry reads use HTTPS only")
            # The token belongs to the registry. Blob storage gets the signed URL alone.
            sent = dict(headers) if target.hostname == REGISTRY else {
                key: value for key, value in headers.items() if key.lower() != "authorization"}
            try:
                with self.opener.open(urllib.request.Request(url, headers=sent), timeout=120) as reply:
                    return reply.read(limit + 1)
            except urllib.error.HTTPError as error:
                location = error.headers.get("Location") if error.code in REDIRECTS else None
                error.close()
                if not location or hop == MAX_REDIRECTS:
                    raise
                url = urllib.parse.urljoin(url, location)
        raise ValueError("too many redirects")

    def fetch(self, kind, digest, limit):
        """Return bytes that hash to `digest`, or fail; never more than `limit`."""
        if not DIGEST.fullmatch(digest):
            raise ValueError("malformed digest")
        url = f"https://{REGISTRY}/v2/{self.repository}/{kind}/{digest}"
        headers = {"Authorization": "Bearer " + self.token, "Accept": ACCEPT if kind == "manifests" else "*/*"}
        for attempt in range(ATTEMPTS):
            try:
                return checked(kind, digest, self._read(url, headers, limit), limit)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                # A digest mismatch is never retried: only a transport failure is.
                status = getattr(error, "code", None)
                if attempt + 1 == ATTEMPTS or (status is not None and status < 500 and status != 429):
                    raise
                time.sleep(2 * (attempt + 1))
        raise ValueError("unreachable")


def document(body):
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("manifest is not a JSON object")
    return value


def is_attestation(entry):
    return (entry.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"


def size_of(descriptor, limit):
    size = descriptor.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= limit:
        raise ValueError("descriptor has an unusable size")
    return size


def platform_manifest(index):
    """Return the descriptor of the one runnable image, which must be plain linux/amd64."""
    entries = index.get("manifests")
    if not isinstance(entries, list) or not entries:
        raise ValueError("index lists no manifests")
    images = []
    for entry in entries:
        if not isinstance(entry, dict) or not DIGEST.fullmatch(str(entry.get("digest"))):
            raise ValueError("index entry has no usable digest")
        if is_attestation(entry):
            continue
        platform = entry.get("platform") or {}
        if (platform.get("os"), platform.get("architecture")) != ("linux", "amd64") or platform.get("variant") \
                or entry.get("mediaType") not in MANIFEST_TYPES:
            raise ValueError("index carries an image this qualification does not cover: "
                             f"{platform.get('os')}/{platform.get('architecture')} {platform.get('variant') or ''}".rstrip())
        images.append(entry)
    if len(images) != 1:
        raise ValueError(f"expected exactly one linux/amd64 image manifest, found {len(images)}")
    return images[0]


def image_manifest(registry, descriptor):
    """Fetch one manifest named by a descriptor and require it to be what the descriptor says."""
    body = registry.fetch("manifests", descriptor["digest"], MAX_MANIFEST)
    manifest = document(body)
    if "size" in descriptor and size_of(descriptor, MAX_MANIFEST) != len(body):
        raise ValueError("manifest size differs from its descriptor")
    if descriptor.get("mediaType") and manifest.get("mediaType") not in (None, descriptor["mediaType"]):
        raise ValueError("manifest media type differs from its descriptor")
    return body, manifest


def blobs_of(registry, manifest):
    """Fetch the config and layers a manifest names, each checked against digest and size."""
    blobs = {}
    descriptors = [manifest.get("config"), *(manifest.get("layers") or [])]
    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            raise ValueError("manifest names no usable config or layer")
        digest = descriptor.get("digest")
        if digest in blobs:
            continue
        size = size_of(descriptor, MAX_BLOB)
        data = registry.fetch("blobs", digest, size)
        if len(data) != size:
            raise ValueError(f"blob {digest} has an unexpected size")
        blobs[digest] = data
    return blobs


def resolve(registry, published):
    """Follow the published digest to the image manifest that a linux/amd64 node runs."""
    body = registry.fetch("manifests", published, MAX_MANIFEST)
    top = document(body)
    media_type = top.get("mediaType")
    if media_type in INDEX_TYPES or (media_type is None and "manifests" in top):
        descriptor = platform_manifest(top)
        body, manifest = image_manifest(registry, descriptor)
        # Everything else the index names must be intact as well: the release later copies
        # the whole index to its version tags.
        for entry in top["manifests"]:
            if entry["digest"] != descriptor["digest"]:
                _, other = image_manifest(registry, entry)
                if isinstance(other.get("config"), dict):
                    blobs_of(registry, other)
        digest, media_type = descriptor["digest"], manifest.get("mediaType") or descriptor["mediaType"]
    else:
        digest, manifest = published, top
    if media_type not in MANIFEST_TYPES or not isinstance(manifest.get("config"), dict) or not manifest.get("layers"):
        raise ValueError("published digest does not lead to an image manifest")
    return digest, media_type, body, manifest


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
    blobs = blobs_of(registry, manifest)
    destination.mkdir(parents=True, exist_ok=True)
    reference = f"localhost/permesi-candidate/{service}:{app_sha}"
    write_archive(destination / f"{service}.tar", reference, digest, media_type, body, blobs)
    return digest


def parse_image(value):
    service, _, reference = value.partition("=")
    match = re.fullmatch(rf"{re.escape(REGISTRY)}/permesi/([a-z]+)@(sha256:[0-9a-f]{{64}})", reference)
    if service not in SERVICES or not match or match.group(1) != service:
        raise argparse.ArgumentTypeError(f"expected <service>={REGISTRY}/permesi/<service>@sha256:<digest>")
    return service, match.group(2)


def main(argv=None, registries=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--app-sha", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--image", action="append", type=parse_image, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.app_sha):
        parser.error("--app-sha must be a full commit")
    images = dict(args.image)
    if sorted(images) != sorted(SERVICES) or len(args.image) != len(SERVICES):
        parser.error("provide exactly one --image for each of permesi, genesis and web")
    resolved = {}
    for service in SERVICES:
        registry = registries[service] if registries else None
        resolved[service] = archive_image(service, images[service], args.app_sha, args.destination, registry)
        print(f"{service}: published {images[service]} runs {resolved[service]}", file=sys.stderr)
    print("platform_digests=" + json.dumps(resolved, sort_keys=True))


if __name__ == "__main__":
    main()
