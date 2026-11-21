# OpenBao refuses to enable audit devices through the API, so the file device is
# declared here and loaded by both the ephemeral and the persistent dev server.
audit "file" "file" {
  options {
    file_path = "/openbao/logs/audit.log"
  }
}
