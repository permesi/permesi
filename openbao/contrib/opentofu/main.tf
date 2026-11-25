terraform {
  # 1.11 adds the write-only attributes and ephemeral variables used for the
  # database root passwords; 1.13 is the tested release.
  required_version = ">= 1.11.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.9.1"
    }
  }

  # State and saved plans hold the OPAQUE seed, the MFA recovery pepper, role IDs
  # and certificates, so they are only written encrypted. The data key comes from
  # a Transit key on the OpenBao this module configures (address and token from
  # BAO_ADDR/BAO_TOKEN). That key must exist before the first apply and is not
  # managed here: a module cannot manage the key that protects its own state.
  # Operators may replace the key provider through TF_ENCRYPTION, which overrides
  # blocks of the same name. State is not `enforced`: that flag cannot be lifted
  # from TF_ENCRYPTION and would also refuse the one-time unencrypted fallback
  # that migrates a plaintext state; the method below already encrypts every
  # write, and `just openbao-tofu-apply` fails if the state is still plaintext.
  encryption {
    key_provider "openbao" "state" {
      transit_engine_path = "/transit/opentofu"
      key_name            = "permesi-state"
    }

    method "aes_gcm" "state" {
      keys = key_provider.openbao.state
    }

    state {
      method = method.aes_gcm.state
    }

    plan {
      method   = method.aes_gcm.state
      enforced = true
    }
  }
}
