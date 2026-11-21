ui = true

# OpenBao dropped the file backend; a single-node Raft store is its persistent default.
storage "raft" {
  path    = "/openbao/file"
  node_id = "permesi-dev"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
