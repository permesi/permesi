#!/usr/bin/env python3
"""Exercise the published-image archiver against a fake registry, without network access."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("archiver", Path(__file__).with_name("release-image-archive.py"))
ARCHIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHIVER)

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
APP = "a" * 40


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class StoredRegistry(ARCHIVER.Registry):
    """The real Registry with only its transport replaced, so every fetch runs the real
    digest, size and retry code against bytes held here."""

    def __init__(self):
        self.objects, self.requests = {}, []
        super().__init__("permesi/permesi", token="test-token", opener=None)

    def put(self, data):
        self.objects[digest(data)] = data
        return digest(data)

    def _read(self, url, headers, limit):
        self.requests.append((url, dict(headers), limit))
        return self.objects[url.rsplit("/", 1)[1]][:limit + 1]


def image(registry, config=b'{"architecture":"amd64"}', layer=b"layer-bytes"):
    manifest = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": registry.put(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": registry.put(layer), "size": len(layer)}]}).encode()
    return {"mediaType": OCI_MANIFEST, "digest": registry.put(manifest), "size": len(manifest)}, manifest, (config, layer)


def published_image(registry, entries=None):
    """A release-shaped index: one linux/amd64 image and a BuildKit attestation by default."""
    descriptor, manifest, blobs = image(registry)
    descriptor["platform"] = {"os": "linux", "architecture": "amd64"}
    attestation, _, _ = image(registry, b'{"statement":1}', b"in-toto")
    attestation.update(platform={"os": "unknown", "architecture": "unknown"},
                       annotations={"vnd.docker.reference.type": "attestation-manifest"})
    listed = [descriptor, attestation] if entries is None else entries(descriptor, attestation)
    index = json.dumps({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": listed}).encode()
    return registry.put(index), descriptor["digest"], manifest, blobs


class Archive(unittest.TestCase):
    def archive(self, registry, published, service="permesi"):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "new" / "candidates"
            ran = ARCHIVER.archive_image(service, published, APP, destination, registry)
            with tarfile.open(destination / f"{service}.tar") as archive:
                return ran, {name: archive.extractfile(name).read() for name in archive.getnames()}

    def refused(self, registry, published):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
            ARCHIVER.archive_image("permesi", published, APP, Path(tmp), registry)
            self.fail("archived")
        self.assertEqual(list(Path(tmp).glob("**/*.tar")) if Path(tmp).exists() else [], [])

    def test_published_index_becomes_a_single_verified_candidate_archive(self):
        registry = StoredRegistry()
        published, platform, manifest, blobs = published_image(registry)
        ran, members = self.archive(registry, published)
        self.assertEqual(ran, platform)
        entry, = json.loads(members["index.json"])["manifests"]
        self.assertEqual(entry["digest"], platform)
        self.assertEqual(entry["annotations"]["org.opencontainers.image.ref.name"],
                         "localhost/permesi-candidate/permesi:" + APP)
        self.assertEqual(members["blobs/sha256/" + platform[7:]], manifest)
        for blob in blobs:
            self.assertEqual(members["blobs/sha256/" + digest(blob)[7:]], blob)
        self.assertEqual(json.loads(members["oci-layout"]), {"imageLayoutVersion": "1.0.0"})
        # Only the image is carried; the index and its attestation are checked, not archived.
        self.assertEqual(len(members), 5)
        fetched = {url.rsplit("/", 1)[1] for url, _, _ in registry.requests}
        self.assertEqual(fetched, set(registry.objects), "every object the index names is fetched and checked")
        for url, headers, _ in registry.requests:
            self.assertTrue(url.startswith("https://ghcr.io/v2/permesi/permesi/"))
            self.assertEqual(headers["Authorization"], "Bearer test-token")

    def test_a_published_single_manifest_is_archived_as_itself(self):
        registry = StoredRegistry()
        descriptor, _, _ = image(registry)
        ran, _ = self.archive(registry, descriptor["digest"], "web")
        self.assertEqual(ran, descriptor["digest"])

    def test_any_object_that_does_not_match_its_digest_stops_the_archive(self):
        registry = StoredRegistry()
        published, _, _, _ = published_image(registry)
        for target in list(registry.objects):
            tampered = StoredRegistry()
            tampered.objects = dict(registry.objects)
            tampered.objects[target] = registry.objects[target] + b" "
            self.refused(tampered, published)

    def test_an_index_with_anything_but_one_plain_linux_amd64_image_is_refused(self):
        arm = {"os": "linux", "architecture": "arm64"}
        cases = {
            "second amd64 image": lambda d, a: [d, dict(d), a],
            "another platform is published": lambda d, a: [d, dict(d, platform=arm), a],
            "only another platform": lambda d, a: [dict(d, platform=arm)],
            "variant": lambda d, a: [dict(d, platform={"os": "linux", "architecture": "amd64", "variant": "v3"})],
            "missing platform": lambda d, a: [{k: v for k, v in d.items() if k != "platform"}],
            "null platform": lambda d, a: [dict(d, platform=None)],
            "only an attestation": lambda d, a: [a],
            "no entries": lambda d, a: [],
            "entry without digest": lambda d, a: [d, {"mediaType": OCI_MANIFEST}],
            "entry is not an object": lambda d, a: [d, "sha256:" + "0" * 64],
            "image entry is an index": lambda d, a: [dict(d, mediaType=OCI_INDEX)],
        }
        for name, entries in cases.items():
            registry = StoredRegistry()
            published, _, _, _ = published_image(registry, entries)
            with self.subTest(name):
                self.refused(registry, published)

    def test_an_attestation_that_claims_a_runnable_platform_is_still_not_the_image(self):
        registry = StoredRegistry()
        amd = {"os": "linux", "architecture": "amd64"}
        published, platform, _, _ = published_image(registry, lambda d, a: [dict(a, platform=amd), d])
        ran, _ = self.archive(registry, published)
        self.assertEqual(ran, platform)

    def test_sizes_and_types_that_disagree_with_their_descriptor_are_refused(self):
        for change in ({"size": 1}, {"size": True}, {"size": -1}, {"size": "9"}, {"size": ARCHIVER.MAX_MANIFEST + 1},
                       {"mediaType": "application/vnd.docker.distribution.manifest.v2+json"}):
            registry = StoredRegistry()
            published, _, _, _ = published_image(registry, lambda d, a, change=change: [dict(d, **change), a])
            with self.subTest(change):
                self.refused(registry, published)
        registry = StoredRegistry()
        config, layer = b"{}", b"layer"
        manifest = json.dumps({"schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": {"digest": registry.put(config), "size": len(config)},
            "layers": [{"digest": registry.put(layer), "size": len(layer) + 1}]}).encode()
        self.refused(registry, registry.put(manifest))
        for body in (b"[]", b'"text"', b"{}", json.dumps({"mediaType": OCI_MANIFEST, "config": {}, "layers": []}).encode()):
            registry = StoredRegistry()
            with self.subTest(body):
                self.refused(registry, registry.put(body))

    def test_a_layer_is_never_read_past_the_size_its_descriptor_states(self):
        registry = StoredRegistry()
        published, _, _, (config, layer) = published_image(registry)
        self.archive(registry, published)
        limits = {url.rsplit("/", 1)[1]: limit for url, _, limit in registry.requests if "/blobs/" in url}
        self.assertEqual(limits[digest(layer)], len(layer))
        self.assertEqual(limits[digest(config)], len(config))

    def test_only_the_three_published_repositories_and_full_digests_are_accepted(self):
        good = "sha256:" + "1" * 64
        self.assertEqual(ARCHIVER.parse_image(f"permesi=ghcr.io/permesi/permesi@{good}"), ("permesi", good))
        for bad in (f"permesi=ghcr.io/permesi/genesis@{good}", f"permesi=ghcr.io/other/permesi@{good}",
                    f"permesi=docker.io/permesi/permesi@{good}", "permesi=ghcr.io/permesi/permesi:0.6.0",
                    f"admin=ghcr.io/permesi/admin@{good}", "permesi=ghcr.io/permesi/permesi@sha256:abc",
                    f"permesi=ghcr.io/permesi/permesi@{good} --extra"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                ARCHIVER.parse_image(bad)

    def test_main_archives_all_three_and_prints_the_platform_digests(self):
        registries, arguments, expected = {}, ["--app-sha", APP], {}
        for service in ARCHIVER.SERVICES:
            registries[service] = StoredRegistry()
            published, expected[service], _, _ = published_image(registries[service])
            arguments += ["--image", f"{service}=ghcr.io/permesi/{service}@{published}"]
        with tempfile.TemporaryDirectory() as tmp:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                ARCHIVER.main(arguments + ["--destination", tmp], registries)
            self.assertEqual(sorted(path.name for path in Path(tmp).iterdir()), ["genesis.tar", "permesi.tar", "web.tar"])
        line, = output.getvalue().splitlines()
        self.assertEqual(json.loads(line.removeprefix("platform_digests=")), expected)
        for bad in (arguments[:-2], arguments + arguments[-2:], ["--app-sha", "abc"] + arguments[2:]):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                ARCHIVER.main(bad + ["--destination", "unused"], registries)


class Reply:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count):
        return self.body[:count]


class Opener:
    """Scripted HTTP replies; records each request's URL and headers."""

    def __init__(self, *replies):
        self.replies, self.seen = list(replies), []

    def open(self, request, timeout):
        self.seen.append((request.full_url, {key.lower(): value for key, value in request.header_items()}))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return Reply(reply)


def redirect(location, code=307):
    return urllib.error.HTTPError("https://ghcr.io/x", code, "redirect", {"Location": location} if location else {}, io.BytesIO())


class Transport(unittest.TestCase):
    def registry(self, *replies):
        opener = Opener(*replies)
        return ARCHIVER.Registry("permesi/permesi", token="secret-token", opener=opener), opener

    def test_the_token_stays_with_the_registry_when_a_blob_redirects_to_storage(self):
        blob = b"layer"
        registry, opener = self.registry(redirect("https://storage.example/signed?sig=1"), blob)
        self.assertEqual(registry.fetch("blobs", digest(blob), len(blob)), blob)
        (first, sent), (second, forwarded) = opener.seen
        self.assertEqual(first, "https://ghcr.io/v2/permesi/permesi/blobs/" + digest(blob))
        self.assertEqual(sent["authorization"], "Bearer secret-token")
        self.assertEqual(second, "https://storage.example/signed?sig=1")
        self.assertNotIn("authorization", forwarded)

    def test_plain_http_missing_locations_and_redirect_loops_are_refused(self):
        blob = b"layer"
        registry, _ = self.registry(redirect("http://storage.example/plain"))
        with self.assertRaises(ValueError):
            registry.fetch("blobs", digest(blob), len(blob))
        registry, _ = self.registry(redirect(None))
        with self.assertRaises(urllib.error.HTTPError):
            registry.fetch("blobs", digest(blob), len(blob))
        registry, opener = self.registry(*[redirect(f"https://storage.example/{hop}") for hop in range(9)])
        with self.assertRaises(urllib.error.HTTPError):
            registry.fetch("blobs", digest(blob), len(blob))
        self.assertEqual(len(opener.seen), ARCHIVER.MAX_REDIRECTS + 1)

    def test_real_fetch_rejects_wrong_bytes_oversize_and_malformed_digests(self):
        blob = b"layer"
        registry, _ = self.registry(b"other")
        with self.assertRaises(ValueError):
            registry.fetch("blobs", digest(blob), 64)
        registry, _ = self.registry(blob)
        with self.assertRaises(ValueError):
            registry.fetch("blobs", digest(blob), len(blob) - 1)
        registry, opener = self.registry(blob)
        for bad in ("sha256:abc", "md5:" + "0" * 32, "../" + digest(blob), digest(blob) + "/x"):
            with self.assertRaises(ValueError):
                registry.fetch("blobs", bad, 64)
        self.assertEqual(opener.seen, [])

    def test_server_errors_are_retried_and_client_errors_are_not(self):
        blob = b"layer"
        failure = lambda code: urllib.error.HTTPError("https://ghcr.io/x", code, "failed", {}, io.BytesIO())
        with mock.patch.object(ARCHIVER.time, "sleep"):
            registry, opener = self.registry(failure(503), blob)
            self.assertEqual(registry.fetch("blobs", digest(blob), len(blob)), blob)
            registry, opener = self.registry(failure(404), blob)
            with self.assertRaises(urllib.error.HTTPError):
                registry.fetch("blobs", digest(blob), len(blob))
            self.assertEqual(len(opener.seen), 1)
            registry, opener = self.registry(b"wrong", blob)
            with self.assertRaises(ValueError):
                registry.fetch("blobs", digest(blob), 64)
            self.assertEqual(len(opener.seen), 1, "a digest mismatch is never retried")

    def test_the_anonymous_token_comes_from_the_registry_over_https(self):
        opener = Opener(b'{"token":"anonymous"}')
        registry = ARCHIVER.Registry("permesi/web", opener=opener)
        self.assertEqual(registry.token, "anonymous")
        (url, headers), = opener.seen
        self.assertEqual(url, "https://ghcr.io/token?scope=repository:permesi/web:pull")
        self.assertNotIn("authorization", headers)


class Wiring(unittest.TestCase):
    def jobs(self):
        release = (ROOT / ".github/workflows/release.yml").read_text().split("\njobs:\n", 1)[1]
        names = re.findall(r"^  ([a-z][a-z-]*):$", release, flags=re.M)
        bodies = re.split(r"^  [a-z][a-z-]*:$", release, flags=re.M)[1:]
        return dict(zip(names, bodies))

    def needs(self, body):
        return set(re.search(r"^    needs: \[([^\]]*)\]", body, flags=re.M).group(1).replace(" ", "").split(","))

    def test_the_release_qualifies_its_own_digests_before_anything_is_published(self):
        jobs = self.jobs()
        qualify = jobs["qualify"]
        self.assertIn("uses: ./.github/workflows/release-qualify.yml", qualify)
        for service in ("permesi", "genesis", "web"):
            self.assertIn(f"{service}_digest: ${{{{ needs.images.outputs.{service}_digest }}}}", qualify)
        self.assertIn("app_sha: ${{ github.sha }}", qualify)
        self.assertNotIn("write", qualify)
        self.assertNotIn("secrets", qualify)
        self.assertLessEqual({"qualify", "images-sign"}, self.needs(jobs["release"]))
        # Everything irreversible hangs off `release`, directly or through a job that does.
        for job in ("images-publish", "deploy-frontend", "docs"):
            self.assertIn("release", self.needs(jobs[job]), job)
        self.assertLessEqual({"images-publish", "qualify"}, self.needs(jobs["helm"]))

    def test_images_are_signed_and_attested_only_after_they_qualify(self):
        jobs = self.jobs()
        for marker in ("cosign", "attest-build-provenance", "id-token: write", "attestations: write"):
            self.assertNotIn(marker, jobs["images"], marker)
        signing = jobs["images-sign"]
        self.assertLessEqual({"images", "qualify"}, self.needs(signing))
        self.assertIn("cosign sign --yes", signing)
        self.assertEqual(signing.count("actions/attest-build-provenance@"), 3)
        for service in ("permesi", "genesis", "web"):
            self.assertIn(f"subject-digest: ${{{{ needs.images.outputs.{service}_digest }}}}", signing)
        self.assertNotIn("steps.push.outputs", signing)

    def test_the_chart_bump_is_dispatched_only_for_the_qualified_chart_revision(self):
        helm = self.jobs()["helm"]
        check = helm.index("QUALIFIED: ${{ needs.qualify.outputs.chart_sha }}")
        self.assertLess(check, helm.index("uses: ./.github/actions/dispatch-helm"))
        self.assertIn('if [[ "$current" != "$QUALIFIED" ]]; then', helm)

    def test_the_qualification_workflow_cannot_write_and_checks_what_ran(self):
        workflow = (ROOT / ".github/workflows/release-qualify.yml").read_text()
        self.assertNotRegex(workflow, r":\s*write\b")
        self.assertNotIn("secrets.", workflow)
        self.assertEqual(workflow.count("ref: ${{ needs.resolve.outputs.chart_sha }}"), 2)
        self.assertIn("if ran != expected:", workflow)
        self.assertIn('record.get("outcome") != "passed"', workflow)
        self.assertIn('[[ "$revision" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertNotIn(">> \"$GITHUB_ENV\"\n", workflow.split("Select the rollback baseline", 1)[0])


if __name__ == "__main__":
    unittest.main()
