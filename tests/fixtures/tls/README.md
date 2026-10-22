# Test-only TLS fixtures

These certificates and the private key are self-signed credentials generated
exclusively for the integration tests. They are not used by the gateway at
runtime and must never be used in a deployment.

The tests use these files to verify certificate validation, SNI matching, and
DNS-over-TLS tunneling without disabling TLS verification.
