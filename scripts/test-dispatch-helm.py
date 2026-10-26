#!/usr/bin/env python3
"""Run the real Helm sender shell blocks and an explicitly supplied real receiver.

Requires Bash, jq and PyYAML. Curl is replaced by a local payload capture executable;
no GitHub token is minted and no network dispatch is possible. Every test owns its
scratch directory, including injection sentinels and GitHub output files.
"""

import argparse
import copy
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ("permesi", "genesis", "web")
RECEIVER = None


class DispatchContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Require real local tooling and read the product action, not copied shell."""
        for binary in ("bash", "jq"):
            if shutil.which(binary) is None:
                raise RuntimeError(f"required dependency not on PATH: {binary}")
        cls.action = yaml.safe_load(
            (ROOT / ".github/actions/dispatch-helm/action.yml").read_text()
        )
        cls.metadata = next(step for step in cls.action["runs"]["steps"] if step.get("id") == "meta")
        cls.dispatch = next(step for step in cls.action["runs"]["steps"] if "run" in step and step is not cls.metadata)

    def setUp(self):
        """Replace only network delivery; preserve actual sender JSON generation."""
        self.temporary = tempfile.TemporaryDirectory(prefix="permesi-helm-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.sentinel = self.directory / "injection-executed"
        self.capture = self.directory / "captured.json"
        curl = self.directory / "curl"
        curl.write_text(
            "#!/usr/bin/env python3\n"
            "import os, pathlib, shutil, sys\n"
            "args = sys.argv[1:]\n"
            "assert 'https://api.github.com/repos/permesi/permesi-helm/dispatches' in args\n"
            "body = args[args.index('--data') + 1]\n"
            "assert body.startswith('@')\n"
            "shutil.copyfile(body[1:], os.environ['DISPATCH_CAPTURE'])\n"
        )
        curl.chmod(0o700)
        self.environment = os.environ | {
            "PATH": str(self.directory) + os.pathsep + os.environ["PATH"],
            "GITHUB_OUTPUT": str(self.directory / "metadata"),
            "GITHUB_REPOSITORY": "permesi/permesi",
            "RUNNER_TEMP": str(self.directory),
            "DISPATCH_CAPTURE": str(self.capture),
        }

    @staticmethod
    def valid_inputs():
        """Use syntactically valid identities without claiming registry provenance."""
        return {
            "version": "v0.4.3",
            "source_sha": "a" * 40,
            **{f"{service}_digest": "sha256:" + digit * 64
               for service, digit in zip(SERVICES, "123", strict=True)},
        }

    def step_environment(self, step, inputs, outputs):
        """Resolve actual action env expressions without evaluating them as shell."""
        values = {f"inputs.{key}": str(value) for key, value in inputs.items()}
        values |= {f"steps.meta.outputs.{key}": value for key, value in outputs.items()}
        values["steps.app-token.outputs.token"] = "local-capture-only"
        environment = self.environment.copy()
        for name, expression in step.get("env", {}).items():
            match = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", expression)
            environment[name] = values[match.group(1)] if match else expression
        return environment

    def sender(self, inputs, repository="permesi/permesi"):
        """Execute validation before delivery, as the composite action does."""
        defaults = {key: str(value.get("default", ""))
                    for key, value in self.action["inputs"].items()}
        inputs = defaults | inputs
        self.environment["GITHUB_REPOSITORY"] = repository
        result = subprocess.run(
            ["bash", "-c", self.metadata["run"]],
            env=self.step_environment(self.metadata, inputs, {}),
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode:
            return result, None
        outputs = dict(line.split("=", 1) for line in Path(self.environment["GITHUB_OUTPUT"]).read_text().splitlines())
        result = subprocess.run(
            ["bash", "-c", self.dispatch["run"]],
            env=self.step_environment(self.dispatch, inputs, outputs),
            capture_output=True, text=True, timeout=15,
        )
        return result, json.loads(self.capture.read_text()) if self.capture.exists() else None

    def receiver(self, payload):
        """Pass actual generated or deliberately malformed JSON to the real receiver."""
        event = self.directory / "event.json"
        output = self.directory / "receiver-output"
        output.unlink(missing_ok=True)
        event.write_text(json.dumps(payload))
        result = subprocess.run(
            ["bash", str(RECEIVER)],
            env=self.environment | {
                "GITHUB_EVENT_NAME": "repository_dispatch",
                "GITHUB_EVENT_PATH": str(event),
                "GITHUB_OUTPUT": str(output),
                "GITHUB_ACTOR": "local-contract-test",
            },
            capture_output=True, text=True, timeout=15,
        )
        return result, dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}

    def test_full_digest_and_explicit_tag_only_reach_receiver(self):
        """Default full digests survive; only explicit true authorizes empty digests."""
        for version, acknowledgement in itertools.product(("0.4.3", "v0.4.3"), (None, "false", "true")):
            with self.subTest(version=version, acknowledgement=acknowledgement):
                inputs = self.valid_inputs() | {"version": version}
                if acknowledgement is not None:
                    inputs["tag_only"] = acknowledgement
                tag_only = acknowledgement == "true"
                if tag_only:
                    inputs |= {f"{service}_digest": "" for service in SERVICES}
                result, payload = self.sender(inputs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIs(payload["client_payload"]["tag_only"], tag_only)
                result, output = self.receiver(payload)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output["mode"], "tag-only" if tag_only else "digest")
                self.assertEqual(output["version"], "0.4.3")
                self.assertEqual(output["source_tag"], version)
                for service in SERVICES:
                    self.assertEqual(output[f"{service}_digest"], inputs[f"{service}_digest"])

    def test_missing_acknowledgement_and_partial_digests_fail_before_delivery(self):
        """Exhaust all digest-presence combinations without inferring authorization."""
        for present in itertools.product((False, True), repeat=3):
            for acknowledgement in (None, "false", "true"):
                if all(present) and acknowledgement != "true" or not any(present) and acknowledgement == "true":
                    continue
                with self.subTest(present=present, acknowledgement=acknowledgement):
                    inputs = self.valid_inputs()
                    for service, enabled in zip(SERVICES, present, strict=True):
                        if not enabled:
                            inputs[f"{service}_digest"] = ""
                    if acknowledgement is not None:
                        inputs["tag_only"] = acknowledgement
                    result, payload = self.sender(inputs)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIsNone(payload)
                    self.assertFalse(self.capture.exists())

    def test_invalid_values_and_shell_injection_fail_before_delivery(self):
        """Treat shell syntax, JSON fragments and output-file injection as data."""
        attack = f"$(touch {self.sentinel})"
        attacks = [attack, f"`touch {self.sentinel}`", f'\"; touch {self.sentinel}; #', f"\nsource_tag={attack}", "\r", "${HOME}"]
        cases = [(key, value) for key in ("version", "source_sha", "tag_only", "permesi_digest", "genesis_digest", "web_digest") for value in attacks]
        cases += [("tag_only", value) for value in ("", "TRUE", "1", "null", "{}", "[]", " false ")]
        cases += [("permesi_digest", value) for value in ("sha256:" + "A" * 64, "sha256:1234", "sha512:" + "a" * 64)]
        cases += [("source_sha", "A" * 40), ("version", "vv0.4.3")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                result, payload = self.sender(self.valid_inputs() | {key: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)
                self.assertFalse(self.capture.exists())
                self.assertFalse(self.sentinel.exists())
        for repository in ("someone/permesi", attack):
            result, payload = self.sender(self.valid_inputs(), repository=repository)
            self.assertNotEqual(result.returncode, 0)
            self.assertIsNone(payload)
            self.assertFalse(self.sentinel.exists())

    def test_receiver_rejects_malformed_generated_payloads_and_injection(self):
        """Validate receiver rejection, not merely the sender's own assumptions."""
        result, valid = self.sender(self.valid_inputs())
        self.assertEqual(result.returncode, 0, result.stderr)
        mutations = [
            ("source_repo", "someone/permesi"), ("source_sha", "A" * 40),
            ("source_tag", "v0.4.4"), ("version", f"$(touch {self.sentinel})"),
            ("source_tag", f"0.4.3\nsource_actor=$(touch {self.sentinel})"),
            ("tag_only", True), ("tag_only", {}),
        ]
        for field, value in mutations:
            payload = copy.deepcopy(valid)
            payload["client_payload"][field] = value
            result, output = self.receiver(payload)
            self.assertNotEqual(result.returncode, 0, field)
            self.assertEqual(output, {})
            self.assertFalse(self.sentinel.exists())
        for service, field, value in [
            ("permesi", "digest", ""), ("genesis", "digest", None),
            ("web", "digest", f"$(touch {self.sentinel})"),
            ("permesi", "repository", "ghcr.io/other/permesi"),
            ("genesis", "tag", "0.4.4"),
        ]:
            payload = copy.deepcopy(valid)
            payload["client_payload"]["images"][service][field] = value
            result, output = self.receiver(payload)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, {})
            self.assertFalse(self.sentinel.exists())
        for acknowledged in (False, None):
            payload = copy.deepcopy(valid)
            for image in payload["client_payload"]["images"].values():
                image["digest"] = ""
            if acknowledged is None:
                del payload["client_payload"]["tag_only"]
            result, output = self.receiver(payload)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, {})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receiver", type=Path, required=True, help="Helm checkout's real scripts/ci/release-event.sh")
    args, unittest_args = parser.parse_known_args()
    RECEIVER = args.receiver.resolve()
    if not RECEIVER.is_file():
        parser.error("--receiver must identify the real release-event.sh")
    unittest.main(argv=[__file__, *unittest_args])
