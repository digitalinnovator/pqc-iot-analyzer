# PQC-Ready IoT Protocol Analyzer

Rust CLI tool for analyzing IoT protocol traffic and assessing post-quantum cryptographic (PQC) readiness. Parses CoAP, MQTT, and RPL packets, detects classical cryptographic primitives, scores quantum vulnerability, and recommends NIST PQC replacements.

## Motivation

FIPS 203/204/205 are finalized. IoT devices ship with 10-20 year lifetimes, meaning devices deployed today with RSA/ECDSA will still be running when CRQCs arrive. Harvest-now-decrypt-later makes this worse: adversaries can record encrypted IoT traffic today and break it retroactively once Shor-capable hardware exists. Sensor data (energy, health, infrastructure) retains long-term value, so HNDL risk in IoT is not hypothetical.

This tool automates PQC readiness assessment for IoT protocol traffic -- detect what crypto is in use, score how exposed it is, and map each vulnerable primitive to its NIST PQC replacement.

## Architecture

```
                          +-------------------+
                          |    CLI (clap)     |
                          |  main.rs          |
                          +--------+----------+
                                   |
                    +--------------+--------------+
                    |                             |
           +-------v--------+          +---------v--------+
           |   protocols/   |          |     report/      |
           |                |          |                  |
           | coap.rs (7252) |          | JSON + Text      |
           | mqtt.rs (3.1.1)|          | report generator |
           | rpl.rs  (6550) |          +--------+---------+
           +-------+--------+                  ^
                   |                            |
           +-------v--------+          +-------+----------+
           |    crypto/     |--------->|    analyzer/     |
           |                |          |                  |
           | TLS suite map  |          | Weighted scoring |
           | OID detection  |          | Category breakdown|
           | RPL sec parse  |          | PQC migration    |
           | Payload heur.  |          | recommendations  |
           +----------------+          +------------------+
```

| Module | Purpose |
|--------|---------|
| `protocols::coap` | CoAP v1 parser (RFC 7252) -- header, options, payload, DTLS record extraction |
| `protocols::mqtt` | MQTT v3.1.1/5.0 parser -- CONNECT, PUBLISH, SUBSCRIBE with TLS detection |
| `protocols::rpl`  | RPL parser (RFC 6550) -- DIS, DIO, DAO with security section parsing |
| `crypto`          | Primitive detection from TLS cipher suites, ASN.1 OIDs, RPL security options, payload heuristics |
| `analyzer`        | Weighted PQC readiness scoring with per-category breakdown |
| `report`          | JSON and formatted text report generation |

## Installation

```bash
git clone https://github.com/digitalinnovator/pqc-iot-analyzer.git
cd pqc-iot-analyzer
cargo build --release
```

## Usage

```bash
# Analyze with text output
pqc-iot-analyzer analyze samples/mixed_traffic.hex

# JSON output
pqc-iot-analyzer analyze samples/coap_dtls.hex --format json

# Filter by protocol
pqc-iot-analyzer analyze samples/mixed_traffic.hex --protocol coap

# Scan for a specific protocol
pqc-iot-analyzer scan samples/mixed_traffic.hex --protocol rpl

# Generate report
pqc-iot-analyzer report samples/coap_dtls.hex --format text

# Show PQC migration mapping table
pqc-iot-analyzer mappings
```

## Example Output

```
========================================================================
  PQC-Ready IoT Protocol Analyzer -- Analysis Report
========================================================================

  PQC Readiness Score:  38/100
  Risk Level:           HIGH
  Packets Analyzed:     5
  Primitives Detected:  6
  Recommendations:      3

  Score: [###############-------------------------] 38/100

------------------------------------------------------------------------
  Category Breakdown
------------------------------------------------------------------------

  Category                  Score   Safe   Vuln    Unk
  ------------------------------------------------------
  Key Exchange                 0%      0      2      0
  Digital Signature            0%      0      2      0
  AEAD                       100%      2      0      0
  Hash Function              100%      1      0      0

------------------------------------------------------------------------
  Detected Cryptographic Primitives
------------------------------------------------------------------------

  Algorithm              Category             PQC Status           Source
  --------------------------------------------------------------------
  AES-128-GCM            AEAD                 [SAFE]               TLS CipherSuite 0xC02B
  AES-256-GCM            AEAD                 [SAFE]               TLS CipherSuite 0x009C
  ECDHE                  Key Exchange         [VULN]               TLS CipherSuite 0xC02B
  ECDSA                  Digital Signature    [VULN]               TLS CipherSuite 0xC02B
  RSA                    Key Exchange         [VULN]               TLS CipherSuite 0x009C
  SHA-256                Hash Function        [SAFE]               TLS CipherSuite 0xC02B

------------------------------------------------------------------------
  PQC Migration Recommendations
------------------------------------------------------------------------

  1. ECDHE --> ML-KEM-768 (FIPS 203)
     Standard: FIPS 203
     ML-KEM replaces ECDH key agreement. Hybrid X25519+ML-KEM-768
     recommended during transition (RFC 9370).

  2. ECDSA --> ML-DSA-44 (FIPS 204)
     Standard: FIPS 204
     ML-DSA replaces ECDSA/EdDSA; ML-DSA-44 targets NIST Level 2,
     comparable to P-256.

  3. RSA --> ML-KEM-768 (FIPS 203)
     Standard: FIPS 203
     ML-KEM (Kyber) replaces RSA key transport with IND-CCA2 secure
     key encapsulation.

========================================================================
  Generated by pqc-iot-analyzer v0.1.0
========================================================================
```

## PQC Migration Mapping

| Classical Algorithm | PQC Replacement | NIST Standard | Type |
|---|---|---|---|
| RSA (key transport) | ML-KEM-768 / ML-KEM-1024 | FIPS 203 | KEM |
| RSA (signatures) | ML-DSA-65 / ML-DSA-87 | FIPS 204 | Signature |
| ECDSA (P-256) | ML-DSA-44 | FIPS 204 | Signature |
| ECDSA (P-384) | ML-DSA-65 | FIPS 204 | Signature |
| Ed25519 / Ed448 | ML-DSA-44 / ML-DSA-65 | FIPS 204 | Signature |
| ECDH (P-256/P-384) | ML-KEM-768 / ML-KEM-1024 | FIPS 203 | KEM |
| X25519 / X448 | ML-KEM-768 / ML-KEM-1024 | FIPS 203 | KEM |
| DH (2048/3072-bit) | ML-KEM-768 / ML-KEM-1024 | FIPS 203 | KEM |
| AES-128 | AES-256 (Grover mitigation) | -- | Symmetric |
| SHA-256 | SHA-256 / SHA-3-256 | FIPS 202 | Hash |

## Scoring Methodology

The PQC readiness score (0-100) is a weighted average across cryptographic primitive categories:

| Category | Weight | Rationale |
|---|---|---|
| Key Exchange | 30% | Directly broken by Shor's algorithm; highest HNDL risk |
| Digital Signature | 30% | Directly broken by Shor's algorithm; authentication compromise |
| Symmetric Cipher | 15% | Grover's halves effective key length; AES-256 remains safe |
| Hash Function | 10% | Quantum speedup is limited; SHA-256+ remains adequate |
| KEM | 10% | Post-quantum key encapsulation presence indicates migration progress |
| AEAD | 5% | Authenticated encryption inherits symmetric cipher security |

Per-category score = ratio of quantum-safe primitives to total detected. Unknown-status primitives count as half-safe.

Risk levels: LOW (80-100), MEDIUM (50-79), HIGH (20-49), CRITICAL (0-19).

## Sample Data Format

Hex-encoded packet data, one packet per line. Lines starting with `#` are comments. Whitespace within hex strings is ignored.

```
# CoAP GET request
4201000100AABB

# MQTT CONNECT v3.1.1
101600044D51545404020038000873656E736F723031
```

## Tests

```bash
cargo test
```

Unit tests cover each protocol parser, crypto detection, and the scoring algorithm. Integration tests verify the full pipeline from hex input to report output.

## References

1. **FIPS 203** -- Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM). NIST, 2024.
2. **FIPS 204** -- Module-Lattice-Based Digital Signature Algorithm Standard (ML-DSA). NIST, 2024.
3. **FIPS 205** -- Stateless Hash-Based Digital Signature Algorithm Standard (SLH-DSA). NIST, 2024.
4. **RFC 7252** -- The Constrained Application Protocol (CoAP). Shelby et al., 2014.
5. **RFC 6347** -- Datagram Transport Layer Security Version 1.2. Rescorla & Modadugu, 2012.
6. **RFC 6550** -- RPL: IPv6 Routing Protocol for Low-Power and Lossy Networks. Winter et al., 2012.
7. **RFC 9431** -- MQTT Version 5.0. OASIS Standard, 2023.
8. **RFC 9370** -- Multiple Key Encapsulation Mechanism (KEM) Hybrid Key Exchange. Stebila et al., 2023.
9. **NIST SP 800-227** -- Recommendations for Transition to Post-Quantum Cryptography. NIST, 2025.
10. Sohail, M.A. et al. "Security Analysis of RPL-based IoT Networks." PLOS ONE.

## Related Work

- **[KeyPact](https://github.com/digitalinnovator/keypact)** -- Hybrid PQC key agreement library in Rust.

## Author

Muhammad Amar Sohail

## License

MIT
