# OPC UA security observations

PLCSEC parses the visible UACP TCP message framing and the unencrypted asymmetric security header in `OPN` (OpenSecureChannel) messages. Where present, it extracts the SecurityPolicy URI, SecureChannel ID, sender-certificate SHA-256 fingerprint and bounded X.509 subject/issuer/expiry metadata.

## Important boundaries

- PLCSEC does not decrypt OPC UA application messages.
- It does not perform certificate-chain validation, revocation checking, trust-list validation or endpoint certificate acceptance checks.
- The OPN asymmetric security header contains a SecurityPolicy URI. It does not, by itself, establish the full server endpoint list or every endpoint's MessageSecurityMode.
- A `SecurityPolicy#None` observation is limited to the captured channel message; it is not a complete audit of all endpoints on the server.
- A fingerprint is an identity aid, not a trust verdict.

The OPC Foundation specification explains the relationship between SecurityPolicies, message security and endpoint descriptions. PLCSEC uses this parser only for passive evidence collection. A human assessor must validate the endpoint configuration through approved vendor tools and site policy before raising a confirmed finding.
