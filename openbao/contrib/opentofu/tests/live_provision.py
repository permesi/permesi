"""Provision a throwaway OpenBao and PostgreSQL from zero with this module, then check
what the services rely on: encrypted state without root passwords, AppRole and cert
auth, dynamic database credentials, Transit, PKI and quotas, the refusals between
the two services, and that OpenBao's root rotation leaves later applies empty."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

MODULE = Path(__file__).resolve().parents[1]
REPO = MODULE.parents[2]
# The permesi-test- prefix lets `just test-clean` and `just doctor` find leftovers.
ID = "permesi-test-e2e-" + uuid.uuid4().hex[:8]
NET, PG, BAO = ID + "-net", ID + "-pg", ID + "-bao"
ROOT = secrets.token_hex(24)
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail and not ok else ""), flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


class Bao:
    def __init__(self, addr, ca):
        self.addr, self.ctx = addr, ssl.create_default_context(cafile=ca)

    def call(self, method, path, token=ROOT, body=None, ctx=None):
        req = Request(self.addr + "/v1/" + path, method=method,
                      data=None if body is None else json.dumps(body).encode(),
                      headers={"X-Vault-Token": token} if token else {})
        try:
            with urlopen(req, timeout=10, context=ctx or self.ctx) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else {}
        except HTTPError as e:
            body = e.read().decode(errors="replace")
            return e.code, {"errors": body[:300]}


def psql_login(user, password, db):
    r = subprocess.run(["podman", "exec", "-e", "PGPASSWORD=" + password, PG, "psql", "-h", PG,
                        "-U", user, "-d", db, "-tAc", "select current_user"], text=True, capture_output=True)
    return r.returncode == 0 and r.stdout.strip() == user


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("openbao_image")
    parser.add_argument("postgres_image")
    args = parser.parse_args()
    work_root = Path(tempfile.mkdtemp(prefix="permesi-e2e-"))
    try:
        run(["podman", "network", "create", NET])
        run(["podman", "run", "-d", "--rm", "--name", PG, "--network", NET, "-e", "POSTGRES_PASSWORD=" + secrets.token_hex(8),
             "-e", "PGDATA=/var/lib/postgresql/data/19", "-v", f"{REPO}/db/sql:/db/sql:ro",
             "-v", f"{REPO}/db/sql/container-entrypoint.sql:/docker-entrypoint-initdb.d/00_init.sql:ro", args.postgres_image])
        run(["podman", "run", "-d", "--rm", "--name", BAO, "--network", NET, "-p", "127.0.0.1::8200",
             "-e", "BAO_DEV_ROOT_TOKEN_ID=" + ROOT, "--entrypoint", "sh", args.openbao_image, "-c",
             "mkdir -p /tmp/tls && exec bao server -dev -dev-tls -dev-tls-cert-dir=/tmp/tls"
             " -dev-listen-address=0.0.0.0:8200"])
        for _ in range(120):
            r = subprocess.run(["podman", "exec", PG, "psql", "-U", "postgres", "-h", "127.0.0.1", "-tAc",
                                "select count(*) from pg_database where datname in ('permesi','genesis')"],
                               text=True, capture_output=True)
            if r.returncode == 0 and r.stdout.strip() == "2":
                break
            time.sleep(.5)
        else:
            raise SystemExit("postgres bootstrap did not finish")
        time.sleep(1)
        ca = work_root / "ca.pem"
        for _ in range(40):
            if subprocess.run(["podman", "cp", f"{BAO}:/tmp/tls/vault-ca.pem", str(ca)], capture_output=True).returncode == 0:
                break
            time.sleep(.25)
        addr = "https://" + run(["podman", "port", BAO, "8200/tcp"]).stdout.strip()
        bao = Bao(addr, str(ca))
        for _ in range(40):
            try:
                if bao.call("GET", "sys/health")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(.25)

        env = {k: v for k, v in os.environ.items() if not k.startswith(("TF_", "VAULT_", "BAO_"))}
        env.update({"VAULT_ADDR": addr, "VAULT_TOKEN": ROOT, "VAULT_CACERT": str(ca),
                    "BAO_ADDR": addr, "BAO_TOKEN": ROOT, "BAO_CACERT": str(ca),
                    "TF_VAR_database_host": PG, "TF_VAR_database_sslmode": "disable",
                    "TF_VAR_permesi_database_password": "change-me", "TF_VAR_genesis_database_password": "change-me"})
        # As `just openbao` does: dev mode's secret/ mount shadows secret/permesi.
        bao.call("DELETE", "sys/mounts/secret")
        # As `just openbao-tofu-apply` does: the state key exists before the first init.
        bao.call("POST", "sys/mounts/transit/opentofu", body={"type": "transit"})
        bao.call("POST", "transit/opentofu/keys/permesi-state", body={"type": "aes256-gcm96"})

        work = work_root / "module"
        work.mkdir()
        for f in [*MODULE.glob("*.tf"), MODULE / ".terraform.lock.hcl"]:
            shutil.copy(f, work / f.name)
        shutil.copytree(MODULE / "policies", work / "policies")
        if (MODULE / ".terraform/providers").is_dir():
            (work / ".terraform").mkdir()
            (work / ".terraform/providers").symlink_to(MODULE / ".terraform/providers", target_is_directory=True)
        tofu = lambda *a, **kw: subprocess.run(["tofu", *a, "-no-color"], cwd=work, env=env, text=True,
                                               capture_output=True, **kw)
        r = tofu("init", "-input=false", "-lockfile=readonly")
        check("tofu init with the committed lock file", r.returncode == 0, r.stderr[-400:])
        r = tofu("apply", "-auto-approve", "-input=false")
        check("fresh apply from zero", r.returncode == 0, (r.stdout + r.stderr)[-1500:])
        if r.returncode:
            return

        raw = (work / "terraform.tfstate").read_text()
        check("state file is encrypted", "encrypted_data" in json.loads(raw) and "opaque_server_seed" not in raw)
        r = tofu("show", "-json")
        connections = []
        if r.returncode == 0:
            resources = json.loads(r.stdout).get("values", {}).get("root_module", {}).get("resources", [])
            connections = [x for x in resources if x["type"] == "vault_database_secret_backend_connection"]
        stored = [c["values"]["postgresql"][0].get(k) for c in connections for k in ("password", "password_wo")]
        ok = len(connections) == 2 and not any(stored) and "change-me" not in r.stdout
        check("decrypted state holds both connections and no root password", ok, f"rc={r.returncode} n={len(connections)}")
        r = tofu("plan", "-input=false", "-out=saved.tfplan")
        plan = (work / "saved.tfplan").read_bytes() if (work / "saved.tfplan").exists() else b""
        shown_plan = tofu("show", "-json", "saved.tfplan") if plan else None
        ok = (r.returncode == 0 and plan and not plan.startswith(b"PK") and b"opaque_server_seed" not in plan
              and shown_plan.returncode == 0)
        check("saved plan is encrypted and still readable with a token", ok, f"rc={r.returncode} head={plan[:2]!r}")
        noenv = {k: v for k, v in env.items() if k not in ("BAO_TOKEN", "VAULT_TOKEN")}
        r = subprocess.run(["tofu", "output", "-json"], cwd=work, env=noenv, text=True, capture_output=True)
        check("state cannot be read without an OpenBao token", r.returncode != 0)
        r = tofu("plan", "-input=false", "-detailed-exitcode")
        check("second plan is empty", r.returncode == 0, r.stdout[-800:])

        outputs = json.loads(tofu("output", "-json").stdout)
        tokens = {}
        for svc in ("permesi", "genesis"):
            sid = bao.call("POST", f"auth/approle/role/{svc}/secret-id")[1]["data"]["secret_id"]
            st, login = bao.call("POST", "auth/approle/login", token=None,
                                 body={"role_id": outputs[f"{svc}_role_id"]["value"], "secret_id": sid})
            ok = st == 200 and login["auth"]["policies"] == [svc]
            check(f"{svc} AppRole login yields only the {svc} policy", ok, str(login.get("auth", {}).get("policies")))
            tokens[svc] = login["auth"]["client_token"] if st == 200 else ""
            st, _ = bao.call("POST", "auth/approle/login", token=None,
                             body={"role_id": outputs[f"{svc}_role_id"]["value"], "secret_id": sid})
            check(f"{svc} SecretID is single-use", st in (400, 403), str(st))

        st, cfg = bao.call("GET", "secret/permesi/data/config", token=tokens["permesi"])
        data = cfg.get("data", {}).get("data", {})
        check("permesi reads the OPAQUE seed and MFA pepper (32 bytes each)", st == 200 and all(
            len(base64.b64decode(data.get(k, ""))) == 32 for k in ("opaque_server_seed", "mfa_recovery_pepper")))
        check("genesis cannot read the permesi config", bao.call("GET", "secret/permesi/data/config", token=tokens["genesis"])[0] == 403)

        leases = {}
        for svc, db in (("permesi", "permesi"), ("genesis", "genesis")):
            st, creds = bao.call("GET", f"database/creds/{svc}", token=tokens[svc])
            ok = st == 200 and psql_login(creds["data"]["username"], creds["data"]["password"], db)
            check(f"{svc} dynamic database credentials log in to {db}", ok, str(st))
            leases[svc] = creds.get("lease_id", "") if st == 200 else ""
        # A stolen service token must not be able to keep another service's database
        # identity alive, nor any other lease: renewal is limited to its own role's leases.
        for svc, other in (("permesi", "genesis"), ("genesis", "permesi")):
            own = bao.call("POST", "sys/leases/renew", token=tokens[svc], body={"lease_id": leases[svc], "increment": 60})[0]
            check(f"{svc} renews its own database lease", own == 200, str(own))
            denied = [bao.call("POST", "sys/leases/renew", token=tokens[svc], body=body)[0] for body in (
                {"lease_id": leases[other]},
                {"lease_id": f"database/creds/{other}/anything"},
                {"lease_id": f"auth/approle/login/{svc}"},
                {"increment": 60},
                {"lease_id": leases[svc], "unexpected": "x"})]
            check(f"{svc} cannot renew the {other} lease, another kind of lease, or pass other parameters",
                  denied == [403] * 5, str(denied))
            path_form = bao.call("POST", f"sys/leases/renew/{leases[other]}", token=tokens[svc])[0]
            check(f"{svc} cannot renew the {other} lease through the path form", path_form == 403, str(path_form))
        check("permesi cannot mint genesis database credentials", bao.call("GET", "database/creds/genesis", token=tokens["permesi"])[0] == 403)
        check("genesis cannot mint permesi database credentials", bao.call("GET", "database/creds/permesi", token=tokens["genesis"])[0] == 403)
        for svc in ("permesi", "genesis"):
            denied = [bao.call("POST", f"transit/opentofu/{op}/permesi-state", token=tokens[svc], body=b)[0]
                      for op, b in (("datakey/plaintext", {}), ("decrypt", {"ciphertext": "vault:v1:AAAA"}))]
            check(f"{svc} cannot use the OpenTofu state key", denied == [403, 403], str(denied))

        msg = base64.b64encode(b"admission").decode()
        st, sig = bao.call("POST", "transit/genesis/sign/genesis-signing", token=tokens["genesis"], body={"input": msg, "key_version": 1})
        check("genesis signs with the Ed25519 admission key", st == 200 and sig["data"]["signature"].startswith("vault:v1:"), str(sig))
        check("permesi cannot sign admission tokens", bao.call("POST", "transit/genesis/sign/genesis-signing", token=tokens["permesi"], body={"input": msg, "key_version": 1})[0] == 403)
        st, _ = bao.call("POST", "transit/permesi/sign/oidc-signing", token=tokens["permesi"], body={"input": msg})
        check("permesi signs with the OIDC key", st == 200)
        st, dk = bao.call("POST", "transit/permesi/datakey/plaintext/totp", token=tokens["permesi"])
        st2, _ = bao.call("POST", "transit/permesi/decrypt/totp", token=tokens["permesi"],
                          body={"ciphertext": dk.get("data", {}).get("ciphertext", "")})
        check("permesi TOTP data key round-trips", st == 200 and st2 == 200)
        denied = [bao.call("POST", path, token=tokens["genesis"], body={"input": msg})[0]
                  for path in ("transit/permesi/sign/oidc-signing", "transit/permesi/datakey/plaintext/totp")]
        check("genesis cannot use the permesi OIDC or TOTP keys", denied == [403, 403], str(denied))

        names = {"permesi": "api.permesi.localhost", "genesis": "genesis.permesi.localhost"}
        certs = {}
        for svc, other in (("permesi", "genesis"), ("genesis", "permesi")):
            st, _ = bao.call("POST", f"pki-int/issue/{svc}-runtime", body={"common_name": names[other]})
            check(f"{svc} runtime role refuses the {other} name", st == 400, str(st))
            for kind in ("runtime", "bootstrap"):
                role = f"{svc}-{kind}"
                st, c = bao.call("POST", f"pki-int/issue/{role}", body={"common_name": names[svc], "ttl": "1h"})
                check(f"{role} issues for {names[svc]}", st == 200, str(st))
                if st == 200:
                    d = work_root / role
                    d.mkdir()
                    (d / "cert.pem").write_text(c["data"]["certificate"])
                    (d / "key.pem").write_text(c["data"]["private_key"])
                    certs[role] = d

        def cert_login(role, agent):
            ctx = ssl.create_default_context(cafile=str(ca))
            ctx.load_cert_chain(str(certs[role] / "cert.pem"), str(certs[role] / "key.pem"))
            return bao.call("POST", "auth/cert/login", token=None, body={"name": agent}, ctx=ctx)

        for svc, other in (("permesi", "genesis"), ("genesis", "permesi")):
            if f"{svc}-bootstrap" in certs:
                st, login = cert_login(f"{svc}-bootstrap", f"{svc}-agent")
                ok = st == 200 and sorted(login["auth"]["policies"]) == sorted([svc, f"{svc}-agent"])
                check(f"{svc} bootstrap certificate logs in to cert auth as {svc}-agent", ok, str(st))
                st, _ = cert_login(f"{svc}-bootstrap", f"{other}-agent")
                check(f"{svc} bootstrap certificate is refused as {other}-agent", st != 200, str(st))
            if f"{svc}-runtime" in certs:
                # OpenBao answers 500 for a key-usage mismatch; what matters is the refusal reason.
                st, login = cert_login(f"{svc}-runtime", f"{svc}-agent")
                refused = st != 200 and "incompatible key usage" in str(login)
                check(f"{svc} runtime certificate is refused by cert auth (server-only)", refused, f"{st} {login}")

        st, q = bao.call("GET", "sys/quotas/rate-limit/genesis-approle")
        check("genesis AppRole quota is in place", st == 200 and q["data"]["role"] == "genesis")

        for svc in ("permesi", "genesis"):
            st, body = bao.call("POST", f"database/rotate-root/{svc}")
            check(f"OpenBao rotates the {svc} root password", st in (200, 204), f"{st} {body}")
        r = tofu("plan", "-input=false", "-detailed-exitcode")
        check("plan stays empty after OpenBao rotates the root passwords", r.returncode == 0, r.stdout[-800:])
        r = tofu("apply", "-auto-approve", "-input=false")
        ok = r.returncode == 0 and "0 added, 0 changed, 0 destroyed" in r.stdout
        check("re-apply after rotation changes nothing", ok, (r.stdout + r.stderr)[-600:])
        for svc in ("permesi", "genesis"):
            st, creds = bao.call("GET", f"database/creds/{svc}", token=tokens[svc])
            check(f"{svc} credentials still work after rotation and re-apply",
                  st == 200 and psql_login(creds["data"]["username"], creds["data"]["password"], svc))
        check("rotated root password is no longer change-me", not psql_login("openbao_permesi", "change-me", "permesi"))
    finally:
        subprocess.run(["podman", "rm", "-f", PG, BAO], capture_output=True)
        subprocess.run(["podman", "network", "rm", NET], capture_output=True)
        shutil.rmtree(work_root, ignore_errors=True)
        failed = [n for n, ok in RESULTS if not ok]
        print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
        if failed:
            sys.exit(1)


if __name__ == "__main__":
    main()
