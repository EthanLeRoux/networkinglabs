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

---

## HTTP Headers

### Acquiring an HTTP header

To get an HTTP header to work with, open any website in a browser and launch dev tools. In this case, Microsoft Edge was used to access the contact page for UWC:

![Request details](/digital%20forensics/decoder%20lab/http%20header/uwcrequestdetails.png)

The timestamp copied from the `Date:` response header was:

```
Mon, 22 Jun 2026 10:38:10 GMT
```

This is an **RFC 7231** formatted timestamp — the standard for HTTP headers. It is intentionally human-readable, broken down as follows:

| Part | Value |
|---|---|
| Day | Monday |
| Date | 22 June 2026 |
| Time | 10:38:10 |
| Timezone | GMT (UTC+0) |

### Decoding in DCode

#### Input format

Set the input type to **Text** and paste the timestamp as-is. DCode forces commas in the display — this is expected behaviour and does not affect the result.

![Format setup](/digital%20forensics/decoder%20lab/http%20header/formatsetup.png)

#### Problems encountered

DCode initially misread the timestamp, returning implausible results (a Windows FILETIME value dated to 1601). This was caused by spacing — the copied timestamp had no spaces between the day, date, and time components, so DCode could not identify the format.

**Resolution:** The epoch equivalent (`1750585090`) was used instead, with the input type switched to **Numeric**.

#### Identifying the correct result

DCode returned results across many timestamp formats. The correct one was identified as **Unix Seconds**, which produced:

| Format | Result |
|---|---|
| Unix Seconds (UTC) | 22/06/2025 09:38:10 |
| Unix Seconds (Local / SAST) | 22/06/2025 11:38:10 |

All other formats (Apple Absolute Time, Chromium, GPS, Nokia, HFS, etc.) produced implausible dates ranging from 1601 to 2105. Unix Seconds was selected because it was the only format that decoded to a realistic, current date — a reliable sanity check when the correct format is unknown.

The local time offset of +2 hours confirmed the SAST timezone (UTC+2).

![Decode results](/digital%20forensics/decoder%20lab/http%20header/dcoderesulthttp.png)

### Key takeaway

HTTP `Date:` headers are RFC 7231 formatted and human-readable by design. When converting to epoch for use in a tool like DCode, the correct decode format is **Unix Seconds**. The format that produces a plausible current date is almost always the right one.

---

## JWT (JSON Web Token)

### What is a JWT?

A JWT is a token used to authenticate users in modern web applications. It consists of three base64-encoded parts separated by dots:

```
header.payload.signature
```

The payload contains claims including timestamps that tell you when the session started and when it expires. Notably, JWTs are encoded, not encrypted, meaning anyone who intercepts one can decode the payload without a key. This makes them highly valuable in a forensic investigation.

### Acquiring a JWT

JWTs can be found in several places during an investigation:

- Network tab in browser devtools — look for an `Authorization: Bearer eyJ...` request header
- Application tab → Local Storage — look for keys like `token`, `access_token`, or `id_token`
- Application tab → Cookies — look for cookie values starting with `eyJ`

In this lab, the JWT was found in the `Authorization: Bearer` response header after logging into a SaaS application under active development:

![JWT found in response header](/digital%20forensics/decoder%20lab/jwt/jwtheader.png)

The full token recovered was:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYmEzY2YyMy02ZmUxLTRlYTAtODAwOC0wMGI5NGE3M2ZlZjYiLCJpYXQiOjE3ODE4NzI5MzMsImV4cCI6MTc4MjQ3NzczM30.eRoGzW8IyhBdUG1BYB3MFiTePGXSrTuT0OlV1vZUdZU
```

### Decoding the payload with jwt.io

The full token was pasted into [jwt.io](https://jwt.io), which automatically split and decoded all three parts. The decoded payload was:

```json
{
  "sub": "fba3cf23-6fe1-4ea0-8008-00b94a73fef6",
  "iat": 1781872933,
  "exp": 1782477733
}
```

![jwt.io decode result](/digital%20forensics/decoder%20lab/jwt/jwtdecoded.png)

The `sub` field is the subject — a unique identifier for the user. The `iat` and `exp` fields are Unix epoch timestamps.

#### Problems encountered

DCode was initially used to decode the base64 payload directly. It returned a Google URL EI Parameter result dated to 2032 — clearly incorrect. DCode is not designed to parse JWT payloads, so jwt.io was used instead to extract the raw JSON and epoch values.

<!-- ![DCode wrong result](/digital%20forensics/decoder%20lab/jwt/dcodewrongresult.png) -->

### Decoding the timestamps in DCode

With the epoch values extracted, each was entered into DCode as **Numeric** and decoded as **Unix Seconds**:

| Claim | Epoch | Unix Seconds (UTC) |
|---|---|---|
| `iat` (issued at) | 1781872933 | 19/06/2026 12:42:13 |
| `exp` (expires at) | 1782477733 | 26/06/2026 12:42:13 |

![DCode iat result](/digital%20forensics/decoder%20lab/jwt/dcodeiat.png)

![DCode exp result](/digital%20forensics/decoder%20lab/jwt/dcodeexp.png)

### Key takeaway

The session was created on **19 June 2026** and was valid until **26 June 2026** — a 7 day window, typical of a refresh token lifecycle. In a forensic investigation this establishes exactly when a user authenticated and how long they had valid access, even if they only logged in once. Because JWTs are only encoded and not encrypted, this information is recoverable from any intercepted token without needing server-side access.