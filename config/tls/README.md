# TLS Material Directory

This directory stores the TLS certificate and private key used by the
PlayrServers management service. Deployment tooling will generate a
self-signed certificate during installation if one is not already
present. Place production certificates here and point the
`MANAGEMENT_SSL_CERTFILE` and `MANAGEMENT_SSL_KEYFILE` environment
variables at the appropriate files. The directory is intentionally kept
empty in source control.
