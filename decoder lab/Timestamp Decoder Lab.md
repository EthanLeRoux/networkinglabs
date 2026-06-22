# Timestamp Decoder Lab

## Overview

A hands-on lab focused on identifying, reading, and decoding timestamps across common real-world sources. Each section is worked through independently, using real samples pulled from live environments rather than generated data.

## Sources Covered

- **HTTP headers** — decoding `Date:`, `Last-Modified:`, and `Expires:` fields from network responses
- **JWTs** — extracting and decoding `iat` and `exp` claims from base64-encoded tokens
- **Log files** — reading timestamps from syslog, access logs, and event logs
- **Unix epoch** — converting epoch values (seconds/milliseconds) to human-readable time

## Approach

Each source is tackled one at a time using real samples from browser devtools, auth flows, log files, or live epoch values.

### HTTP Headers
