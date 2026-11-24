# DNP3 link CRC handling

PLCSEC 0.6.0 validates CRC-16/DNP on DNP3 link frames. The reflected polynomial is `0xA6BC`, initial register `0x0000`, final XOR `0xFFFF`; the transmitted two-byte CRC is little-endian. The known check value for ASCII `123456789` is `0xEA82`.

The first eight octets (`05 64`, length, control, destination and source) are protected by the header CRC. Each subsequent user-data block of at most 16 octets is followed by its own CRC. CRC bytes are not counted in the DNP3 length field.

CRC errors are retained in parser output and summarized as low-severity observations. They can indicate capture truncation, line noise, malformed traffic or packet modification. CRC is not cryptographic authentication and cannot establish a malicious actor.

The implementation does not reassemble DNP3 transport fragments, verify Secure Authentication, decode all application objects or claim DNP3 conformance.
