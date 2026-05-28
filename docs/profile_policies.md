# Profile Completeness Policies

## `ciso_daily`

The `ciso_daily` profile is report-grade and uses minimum evidence sets by target type. When
`require_profile_complete=false`, missing coverage is reported as partial output. When
`require_profile_complete=true`, missing coverage fails the schema v1 result with a structured
`profile_incomplete:ciso_daily` error.

Minimum evidence sets:

| Target type | Required coverage |
| --- | --- |
| IP | At least one reputation provider: `virustotal`, `abuseipdb`, or `otx`; and at least one context provider: `ipinfo`, `shodan`, `asn_meta`, or `cloudflare_asn`. |
| Domain | At least one reputation provider: `virustotal` or `otx`; and at least one domain-to-IP relationship from passive DNS or resolver-passive DNS. |
| URL | A parser relationship proving the contained domain; and at least one URL reputation provider: `virustotal` or `otx`. |
| ASN | At least one ASN context provider: `ipinfo` or `cloudflare_asn`. |

Optional provider outages, missing credentials, or unavailable passive evidence are allowed under
`best_effort` and under `ciso_daily` when completeness is not required. They remain visible in
`provider_status`, `warnings`, and `errors` so downstream reports can distinguish partial coverage
from complete coverage.

