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

The payload contains claims — including timestamps that tell you when the session started and when it expires. Crucially, JWTs are encoded, not encrypted, meaning anyone who intercepts one can decode the payload without a key. This makes them highly valuable in a forensic investigation.

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

The `sub` field is the subject — a unique identifier for the user. The `iat` and `exp` fields are Unix epoch timestamps — plain integers representing a point in time as a count of seconds elapsed since 1 January 1970 00:00:00 UTC.

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

---

## Log Files

### What are system logs?

System logs record events on a machine — service changes, authentication attempts, process activity, errors. Each entry includes a timestamp, event ID, source, and context. They are a primary evidence source in digital forensic investigations.

### Acquiring a log entry

Windows Event Viewer was used to retrieve a real system log entry. Opened via `Win + R → eventvwr`, navigating to **Windows Logs → System** and selecting an event in the detailed (XML) view.

![Event Viewer entry](/digital%20forensics/decoder%20lab/logs/eventviewerentry.png)

The full event captured was:

```
- System
  - Provider
     [ Name]  Service Control Manager
     [ Guid]  {555908d1-a6d7-4695-8e1e-26931d2012f4}
  - EventID 7040
     [ Qualifiers]  16384
  - TimeCreated
     [ SystemTime]  2026-06-22T11:57:56.2991034Z
    EventRecordID 24532
  - Execution
     [ ProcessID]  884
     [ ThreadID]  1224
    Channel System
    Computer number1
  - Security
     [ UserID]  x-x-x-xx
- EventData
  param1 Background Intelligent Transfer Service
  param2 auto start
  param3 demand start
  param4 BITS
```

Key fields at a glance:

| Field | Value | Meaning |
|---|---|---|
| EventID | 7040 | Service startup type changed |
| TimeCreated | 2026-06-22T11:57:56.2991034Z | When it happened |
| ProcessID | 884 | Process that triggered it |
| UserID | S-1-5-18 | SYSTEM account — OS-level action |
| Computer | number1 | Machine it occurred on |
| EventData | BITS: auto start → demand start | What changed |

The timestamp format is **ISO 8601** — identifiable by three characteristics: the `yyyy-MM-dd` date order with dashes, the `T` separator between date and time, and the `Z` suffix denoting UTC (Zulu time). Once recognised, ISO 8601 is human-readable without any decoding. The value and meaning are visible at a glance.

### What this log entry tells us

In an investigation this event is significant because BITS (Background Intelligent Transfer Service) is commonly abused by malware for stealthy file downloads. A change to its startup type warrants investigation. Combined with the ProcessID and timestamp, this entry can be correlated against other logs to build a timeline and determine whether the change was legitimate or suspicious.

### Decoding the timestamp

#### Why use DCode if the timestamp is already readable?

DCode's value is not in reading human-readable formats like ISO 8601 or RFC 7231. Those can be read directly. DCode is essential when timestamps are raw numbers with no formatting: Windows FILETIME values from registry keys, Chromium timestamps from browser artifacts, GPS time from device logs, or any epoch value pulled from a binary file or database. In those cases DCode takes an unknown number, runs it against every known format simultaneously, and identifies the correct one by which result produces a plausible current date.

For this lab, DCode is used to practice that workflow, converting the ISO 8601 timestamp to epoch first, then decoding it as Unix Seconds.

#### Problems encountered

DCode does not handle ISO 8601 timestamps well. Three variations were attempted:

- Full timestamp with fractional seconds: `2026-06-22T11:57:56.2991034Z` → wrong result
- Stripped fractional seconds: `2026-06-22T11:57:56Z` → wrong result
- Stripped Z suffix: `2026-06-22T11:57:56` → wrong result

DCode returned a Windows FILETIME value dated to 1601 in all cases.

**Resolution:** The timestamp was converted to Unix epoch first using [epochconverter.com](https://www.epochconverter.com), which returned:

```
1782129476
```

The decimal portion (`.299`) was dropped — epoch timestamps are whole seconds. The fractional part represents milliseconds, which would require the **Unix Milliseconds** format and multiplying the value by 1000. For this lab Unix Seconds is sufficient.

![Epoch converter result](/digital%20forensics/decoder%20lab/logs/epochconverter.png)

#### Decoding in DCode

The epoch value `1782129476` was entered into DCode as **Numeric**. The correct result was identified as **Unix Seconds**:

| Format | Result |
|---|---|
| Unix Seconds (UTC) | 22/06/2026 11:57:56 |
| Unix Seconds (Local / SAST) | 22/06/2026 13:57:56 |

![DCode log result](/digital%20forensics/decoder%20lab/logs/dcodelogresult.png)

### Key takeaway

System log timestamps are ISO 8601 formatted and human-readable by design. DCode cannot parse them directly — convert to Unix epoch first using a tool like [epochconverter.com](https://www.epochconverter.com), then decode as Unix Seconds. The decoded timestamp, combined with the EventID, ProcessID, and UserID, gives a complete forensic picture of what happened, when, and under which account.

---

## Unix Epoch

### What is a Unix epoch value?

An epoch value is a plain integer representing a point in time as a count of seconds (or milliseconds) elapsed since **1 January 1970 00:00:00 UTC** — known as the Unix epoch. There is no formatting, no timezone label, no human-readable structure — just a number.

For example:
- `0` = 1 Jan 1970 00:00:00 UTC
- `1750585090` = 22 Jun 2026 10:38:10 UTC

Almost every programming language, database, and operating system stores time this way internally because it is simple to calculate with — subtraction gives duration, comparison gives order.

### Seconds vs milliseconds

The two variants encountered in practice:

| Variant | Digit count | Example |
|---|---|---|
| Unix Seconds | 10 digits | `1782129476` |
| Unix Milliseconds | 13 digits | `1782129476299` |

The digit count is the quickest way to tell them apart at a glance. When in doubt, run both through DCode and pick the result that produces a plausible current date.

### Where epoch values appear

Epoch timestamps were encountered throughout this lab as the underlying representation behind every other format:

- HTTP headers converted to epoch for DCode input
- JWT `iat` and `exp` claims are epoch values in the raw payload
- ISO 8601 log timestamps converted to epoch via epochconverter.com before decoding

In a forensic investigation, raw epoch values commonly appear in registry keys, database records, binary file metadata, and network packet captures — often with no label indicating what format they are.

### Decoding in DCode

Enter the value as **Numeric** and identify **Unix Seconds** (or Unix Milliseconds for 13-digit values) as the correct row. All other formats will produce implausible dates. The format that returns a realistic current date is the right one.

### Key takeaway

Epoch is the common underlying format that most timestamp types reduce to. Recognising it by digit count, knowing whether to use seconds or milliseconds, and being able to convert to and from human-readable formats are foundational forensic skills that apply across every source covered in this lab.

---

## Tools Reference

| Tool | Purpose | URL |
|---|---|---|
| DCode | Decode timestamps across multiple formats | — |
| jwt.io | Decode and inspect JWT tokens | [jwt.io](https://jwt.io) |
| Epoch Converter | Convert human-readable dates to Unix epoch and back | [epochconverter.com](https://www.epochconverter.com) |