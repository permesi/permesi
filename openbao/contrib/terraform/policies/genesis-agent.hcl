path "pki-int/issue/genesis-runtime" {
  capabilities = ["create", "update"]
}

path "pki-int/ca" {
  capabilities = ["read"]
}

path "pki-int/ca_chain" {
  capabilities = ["read"]
}

# JSON PEM chain used by the OpenBao Agent pkiCert template.
path "pki-int/cert/ca_chain" {
  capabilities = ["read"]
}
