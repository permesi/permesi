#!/usr/bin/env python3
"""Exercise the published-image archiver against a fake registry, without network access."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("archiver", Path(__file__).with_name("release-image-archive.py"))
ARCHIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVER)

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
APP = "a" * 40


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeRegistry:
    """Serves stored bytes through the real digest check, so tampering is observable."""

    def __init__(self):
        self.objects = {}

    def put(self, data):
        self.objects[digest(data)] = data
        return digest(data)

    def fetch(self, kind, wanted, limit, accept="*/*"):
        data = self.objects[wanted]
        if len(data) > limit or digest(data) != wanted:
            raise ValueError(f"{kind} {wanted} does not match its digest")
        return data


def published_image(registry, attestation=True, extra_platform=None):
    """A release-shaped index: one linux/amd64 image, a BuildKit attestation, optional others."""
    config, layer = b'{"architecture":"amd64"}', b"layer-bytes"
    manifest = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": registry.put(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": registry.put(layer), "size": len(layer)}]}).encode()
    entries = [{"mediaType": OCI_MANIFEST, "digest": registry.put(manifest), "size": len(manifest),
                "platform": {"os": "linux", "architecture": "amd64"}}]
    if attestation:
        statement = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {}, "layers": []}).encode()
        entries.append({"mediaType": OCI_MANIFEST, "digest": registry.put(statement), "size": len(statement),
                        "platform": {"os": "unknown", "architecture": "unknown"},
                        "annotations": {"vnd.docker.reference.type": "attestation-manifest"}})
    if extra_platform:
        entries.append({"mediaType": OCI_MANIFEST, "digest": entries[0]["digest"], "size": len(manifest), "platform": extra_platform})
    index = json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": entries}).encode()
    return registry.put(index), entries[0]["digest"], manifest, (config, layer)


class Archive(unittest.TestCase):
    def test_published_index_becomes_a_single_verified_candidate_archive(self):
        registry = FakeRegistry()
        published, platform, manifest, blobs = published_image(registry)
        with tempfile.TemporaryDirectory() as tmp:
            ran = ARCHIVER.archive_image("permesi", published, APP, Path(tmp), registry)
            self.assertEqual(ran, platform)
            with tarfile.open(Path(tmp) / "permesi.tar") as archive:
                index = json.load(archive.extractfile("index.json"))
                entry, = index["manifests"]
                self.assertEqual(entry["digest"], platform)
                self.assertEqual(entry["annotations"]["org.opencontainers.image.ref.name"],
                                 "localhost/permesi-candidate/permesi:" + APP)
                self.assertEqual(archive.extractfile("blobs/sha256/" + platform[7:]).read(), manifest)
                for blob in blobs:
                    self.assertEqual(archive.extractfile("blobs/sha256/" + digest(blob)[7:]).read(), blob)
                self.assertEqual(json.load(archive.extractfile("oci-layout")), {"imageLayoutVersion": "1.0.0"})
                # Only the image is carried: the index and its attestation stay behind.
                self.assertEqual(len(archive.getnames()), 5)

    def test_a_published_single_manifest_is_archived_as_itself(self):
        registry = FakeRegistry()
        _, platform, _, _ = published_image(registry)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(ARCHIVER.archive_image("web", platform, APP, Path(tmp), registry), platform)

    def test_any_blob_that_does_not_match_its_digest_stops_the_archive(self):
        for victim in ("index", "manifest", "config", "layer"):
            registry = FakeRegistry()
            published, platform, manifest, (config, layer) = published_image(registry)
            target = {"index": published, "manifest": platform, "config": digest(config), "layer": digest(layer)}[victim]
            registry.objects[target] = registry.objects[target] + b" "
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError, msg=victim):
                ARCHIVER.archive_image("permesi", published, APP, Path(tmp), registry)
            self.assertFalse(list(Path(tmp).glob("*.tar")) if Path(tmp).exists() else [])

    def test_an_index_without_exactly_one_runnable_image_is_refused(self):
        registry = FakeRegistry()
        ambiguous, _, _, _ = published_image(registry, extra_platform={"os": "linux", "architecture": "amd64"})
        only_attestation = registry.put(json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": "sha256:" + "0" * 64, "platform": {"os": "unknown", "architecture": "unknown"}}]}).encode())
        arm_only = registry.put(json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": [
            {"mediaType": OCI_MANIFEST, "digest": "sha256:" + "0" * 64, "platform": {"os": "linux", "architecture": "arm64"}}]}).encode())
        for published in (ambiguous, only_attestation, arm_only):
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                ARCHIVER.archive_image("permesi", published, APP, Path(tmp), registry)

    def test_a_size_that_disagrees_with_the_manifest_is_refused(self):
        registry = FakeRegistry()
        config, layer = b"{}", b"layer"
        manifest = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"digest": registry.put(config), "size": len(config)},
            "layers": [{"digest": registry.put(layer), "size": len(layer) + 1}]}).encode()
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            ARCHIVER.archive_image("permesi", registry.put(manifest), APP, Path(tmp), registry)

    def test_only_the_three_published_repositories_and_full_digests_are_accepted(self):
        good = "sha256:" + "1" * 64
        self.assertEqual(ARCHIVER.parse_image(f"permesi=ghcr.io/permesi/permesi@{good}"), ("permesi", good))
        for bad in (f"permesi=ghcr.io/permesi/genesis@{good}", f"permesi=ghcr.io/other/permesi@{good}",
                    f"permesi=docker.io/permesi/permesi@{good}", "permesi=ghcr.io/permesi/permesi:0.6.0",
                    f"admin=ghcr.io/permesi/admin@{good}", "permesi=ghcr.io/permesi/permesi@sha256:abc",
                    f"permesi=ghcr.io/permesi/permesi@{good} --extra"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                ARCHIVER.parse_image(bad)


class Wiring(unittest.TestCase):
    def test_the_release_qualifies_its_own_digests_before_anything_is_published(self):
        release = (ROOT / ".github/workflows/release.yml").read_text()
        qualify = release.split("\n  qualify:\n", 1)[1].split("\n  release:\n", 1)[0]
        self.assertIn("uses: ./.github/workflows/release-qualify.yml", qualify)
        for service in ("permesi", "genesis", "web"):
            self.assertIn(f"{service}_digest: ${{{{ needs.images.outputs.{service}_digest }}}}", qualify)
        self.assertIn("app_sha: ${{ github.sha }}", qualify)
        self.assertNotIn("write", qualify)
        publish = release.split("\n  release:\n", 1)[1].split("\n    steps:\n", 1)[0]
        self.assertRegex(publish, r"needs: \[[^\]]*\bqualify\b[^\]]*\]")

    def test_the_qualification_workflow_cannot_write_and_checks_what_ran(self):
        workflow = (ROOT / ".github/workflows/release-qualify.yml").read_text()
        self.assertNotRegex(workflow, r":\s*write\b")
        self.assertIn("ref: ${{ needs.resolve.outputs.chart_sha }}", workflow)
        self.assertIn("if ran != expected:", workflow)
        self.assertIn('record.get("outcome") != "passed"', workflow)


if __name__ == "__main__":
    unittest.main()
