"""Apply only Genesis quotas and their prerequisites to an empty disposable OpenBao."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen
import uuid


def main():
    """Verify fresh PKI bootstrap and server-side path, role, rate and interval for each quota."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="OpenBao repository@sha256 image to run with Podman")
    image = parser.parse_args().image
    if not re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", image):
        parser.error("an immutable OpenBao image is required")
    module = Path(__file__).resolve().parents[1]
    name = "permesi-test-quotas-" + uuid.uuid4().hex[:12]
    token = secrets.token_hex(32)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("TF_", "VAULT_", "BAO_"))}
    env.update({"BAO_DEV_ROOT_TOKEN_ID": token, "VAULT_TOKEN": token, "BAO_TOKEN": token,
           "TF_VAR_genesis_database_password": secrets.token_hex(16),
           "TF_VAR_permesi_database_password": secrets.token_hex(16)})
    with tempfile.TemporaryDirectory(prefix="permesi-quotas-") as directory:
        work = Path(directory)
        for source in [*module.glob("*.tf"), module / ".terraform.lock.hcl"]:
            shutil.copy(source, work / source.name)
        shutil.copytree(module / "policies", work / "policies")
        providers = module / ".terraform/providers"
        subprocess.run(["podman", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::8200",
                        "-e", "BAO_DEV_ROOT_TOKEN_ID", image, "server", "-dev", "-dev-listen-address=0.0.0.0:8200"],
                       env=env, check=True, stdout=subprocess.DEVNULL)
        try:
            address = subprocess.check_output(["podman", "port", name, "8200/tcp"], text=True).strip()
            env["VAULT_ADDR"] = "http://" + address
            for attempt in range(40):
                try:
                    with urlopen(env["VAULT_ADDR"] + "/v1/sys/health", timeout=1):
                        break
                except OSError:
                    if attempt == 39:
                        raise
                    time.sleep(.25)
            env["BAO_ADDR"] = env["VAULT_ADDR"]
            # The module only writes encrypted state, under this Transit key.
            for path, body in [("sys/mounts/transit/opentofu", {"type": "transit"}),
                               ("transit/opentofu/keys/permesi-state", {"type": "aes256-gcm96"})]:
                urlopen(Request(env["VAULT_ADDR"] + "/v1/" + path, data=json.dumps(body).encode(), method="POST",
                                headers={"X-Vault-Token": token}), timeout=5).close()
            if providers.is_dir():
                (work / ".terraform").mkdir()
                (work / ".terraform/providers").symlink_to(providers, target_is_directory=True)
            subprocess.run(["tofu", "init", "-lockfile=readonly", "-input=false"], cwd=work, env=env, check=True,
                           stdout=subprocess.DEVNULL)
            subprocess.run(["tofu", "apply", "-target=vault_quota_rate_limit.genesis", "-auto-approve",
                            "-input=false"], env=env, cwd=work, check=True, stdout=subprocess.DEVNULL)
            expected = {"signing": ("transit/genesis/sign/genesis-signing", ""),
                        "credentials": ("database/creds/genesis", ""), "pki": ("pki-int/issue/genesis-runtime", ""),
                        "bootstrap": ("pki-int/issue/genesis-bootstrap", ""), "cert": ("auth/cert", "genesis-agent"),
                        "approle": ("auth/approle", "genesis")}
            for key, (path, role) in expected.items():
                query = Request(env["VAULT_ADDR"] + "/v1/sys/quotas/rate-limit/genesis-" + key,
                                headers={"X-Vault-Token": token})
                with urlopen(query, timeout=5) as response:
                    quota = json.load(response)["data"]
                if (quota["path"].rstrip("/") != path or quota["role"] != role or float(quota["rate"]) != 30
                        or int(quota["interval"]) != 1):
                    raise ValueError("unexpected rate quota for " + key)
                print("Verified Genesis quota for " + key)
        finally:
            subprocess.run(["podman", "stop", "--time", "1", name], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
