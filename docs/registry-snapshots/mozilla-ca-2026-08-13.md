# Mozilla CA bundle snapshot

- Source: <https://curl.se/ca/cacert-2026-08-13.pem>
- Mozilla update date: 2026-08-13
- Certificates: 121
- SHA-256: `f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`
- License: MPL-2.0, inherited from Mozilla's source certificate store
- Generator: `tools/dev/generate_ca_bundle.py`
- Generated source: `src/core/ca_bundle_data.c`

The curl CA Extract service converts Mozilla's certificate store to PEM. The
PEM contains CA signatures but does not carry Firefox-specific name constraints.
The HTTPS proxy implementation must therefore treat this snapshot as a standard
OpenSSL CA file, not as a complete reproduction of Firefox trust policy.