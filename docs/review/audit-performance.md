# tripper_recon — Audit: async correctness, concurrency, latency

Lens: async correctness, concurrency and latency. Read-only review of
`/home/echo/dev/tripper_recon` @ `feat/work-20260808-recon-hardening`.
No network calls were made and the tool was not run against any target. `.env` was not opened.

Where I state a behaviour of `httpx` or `asyncio`, I verified it by running an isolated probe in the
scratchpad against the installed libraries (Python 3.12.13, httpx from
`/home/echo/ACC/ACC-OWASP-App/.venv`). Probe transcripts are quoted inline. Where I state a provider's
published quota I am repeating the task brief and have **not** verified it against vendor documentation —
those are marked `[unverified]`.

---

## Latency model used throughout

I have no measured RTTs for this tool (no network calls permitted), so the arithmetic below is stated as a
formula plus a nominal substitution. Substitute measured values before quoting any number externally.

| Symbol | Meaning | Nominal used |
|---|---|---|
| `R` | one warm provider request/response round trip | **400 ms** |
| `H` | one cold TCP+TLS handshake (≈2 network RTT + cert verify) | **150 ms** |
| `K` | IP addresses resolved for a domain | varies |
| `N` | targets in a bulk IP file | varies |

Counting **serial** round trips is the part that is not a guess — it follows from the code and is what the
restructures below change. The millisecond figures are the soft part.

---

## Findings, ordered by wall-clock / usability impact on a bulk run

---

### F1 — `RateLimiter` constrains nothing. There is no concurrency control anywhere in the tool.
**`tripper_recon/utils/http.py:61-73`, `tripper_recon/orchestrators.py:117-129`** — severity **critical**

`investigate_ip` wraps each `asyncio.create_task(...)` in `async with limiter:`:

```python
# orchestrators.py:120-129
async with limiter:
    vt_task = asyncio.create_task(vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip))
async with limiter:
    ipi_task = asyncio.create_task(ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip))
...
```

`asyncio.create_task` **schedules** a coroutine and returns immediately. It performs no I/O and does not
yield. So the semaphore is acquired and released around a body that does nothing. The HTTP request runs
after the block has exited and the loop next yields — entirely outside the semaphore. The limiter guards
task *creation*, not task *execution*.

Verified with a probe that reproduces the exact pattern:

```
PROBE2 requested limit=5 -> observed peak concurrency: 20
```

Twenty simulated provider calls ran concurrently against a requested limit of 5. The semaphore's internal
value never dropped below 4 (acquire and release with no await between them), so it could not have blocked
even in principle.

Consequences, in order:

1. `investigate_ip` fires all 5 providers at once. That is what you want for a single target — but it is
   accidental, not designed, and it is unbounded.
2. `cli.py:150-151` gathers `investigate_ip` over every line of a bulk file with no cap:
   ```python
   tasks = [investigate_ip(t) for t in targets]
   gathered = await asyncio.gather(*tasks, return_exceptions=True)
   ```
   A 200-line IP list issues **~1,000 concurrent HTTP requests** within a few hundred milliseconds. See F2
   for what that does to your API quota.
3. `--rate-limit` is dead. `configure_rate_limit` (`http.py:57-59`) writes `_init_rate`, which is only read
   when `rate is None` (`http.py:65`). The sole construction site passes `rate=5` explicitly
   (`orchestrators.py:117`), so `_init_rate` is never consulted. Confirmed by grep: `RateLimiter` is
   constructed in exactly one place. `Settings.rate_limit` (`types/models.py:19`) is likewise never read.

**Fix.** The semaphore must be held *around the await*, which means it belongs inside the provider call, not
around task creation:

```python
async def _limited(sem: asyncio.Semaphore, coro):
    async with sem:
        return await coro
```

and then `asyncio.create_task(_limited(sem, vt_ip_summary(...)))`. But see F2 first — a concurrency
semaphore is the wrong instrument for the actual constraint, and F8 is a landmine that this fix triggers.

---

### F2 — No per-provider rate budget exists; 429s are retried blindly, amplifying a quota breach 4×
**`tripper_recon/utils/backoff.py:10-29`; every provider module** — severity **critical**

Grep for `429`, `Retry-After`, `quota`, `per.minute` across the repo returns nothing but the dead
`--rate-limit` flag and a README claim. There is no per-provider budget, no token bucket, no
`Retry-After` handling.

`with_exponential_backoff` (`backoff.py:18-27`) retries on **any** exception, `retries=3` → 4 attempts,
delays 0.5 / 1.0 / 2.0 s plus up to 25 % jitter ≈ 3.5–4.4 s of sleeping. The providers that call
`r.raise_for_status()` turn a 429 into an `HTTPStatusError`, which the backoff then retries:
`virustotal.py:22`, `shodan_api.py:21`, `abuseipdb.py:25`, `ipinfo.py:19`, `otx.py:22`, `otx.py:45`.

Worked example — `tripper-recon ip suspicious_ips.txt` with N = 200 and VirusTotal free tier
(4 req/min, 500/day `[unverified]`):

| Step | Count |
|---|---|
| VT requests fired in the first ~1 s | 200 |
| Expected to succeed under a 4/min budget | ~4 |
| 429 responses | ~196 |
| Retries triggered (3 each) | ~588 |
| **Total VT requests issued in ~5 s** | **~788** |
| Daily quota `[unverified]` | 500 |

One bulk run exhausts the day's VirusTotal quota and returns nothing useful. The same shape applies to
AbuseIPDB's daily cap `[unverified]` — 200 targets is 200 checks against that cap in a single command, with
retry amplification on top.

**The output makes this worse, not visible.** When VT fails, `orchestrators.py:181` writes
`data["virustotal"] = {}`, and `reporting/console.py:70-79` then renders:

```python
malicious = int(vt_stats.get("malicious", 0) or 0)   # -> 0
total_engines = sum(...)                             # -> 0
vt_color = "red" if malicious > 0 else "green"       # -> green
table.add_row("virustotal_detections", f"[{vt_color}]{malicious}/{total_engines}[/]")
```

A rate-limited VirusTotal lookup renders as a **green `0/0`** — the same colour as a clean verdict. There is
a `provider_errors` sub-table below (`console.py:134-161`), but across 200 rendered panels the headline
field is green and wrong. For a tool whose stated job is "is this malicious?" under time pressure, an
unavailable provider that reads as *clean* is the most expensive failure in the codebase.

The README claims the opposite: *"built-in jittered exponential backoff for handling rate limits
(429 Too Many Requests) elegantly"* (`README.md:24`). Blind retry of a 429 without honouring `Retry-After`
is the standard way to get an API key suspended, not elegant handling.

**Fix, in three parts.**

1. **A token bucket per provider, not a semaphore.** A semaphore bounds *concurrency*; VT's limit is a
   *rate*. Concurrency 1 at 400 ms RTT still yields 150 req/min. These are different constraints and the
   current design cannot express the one that matters.
   ```python
   # utils/ratelimit.py
   @dataclass(frozen=True)
   class RateSpec:
       per_minute: int | None = None
       per_day: int | None = None
       max_concurrent: int = 4

   PROVIDER_LIMITS = {                 # verify each against vendor docs before trusting
       "virustotal": RateSpec(per_minute=4, per_day=500, max_concurrent=1),
       "abuseipdb":  RateSpec(per_day=1000, max_concurrent=4),
       "shodan":     RateSpec(per_minute=60, max_concurrent=2),
       "otx":        RateSpec(max_concurrent=4),
       "ipinfo":     RateSpec(max_concurrent=8),
       "ripestat":   RateSpec(max_concurrent=4),
   }
   ```
   Hold the bucket around the `await`, keyed by provider name, and make the buckets loop-local (F8).
2. **Honour `Retry-After` and stop retrying what cannot succeed.** See F11.
3. **Never render an unavailable provider as a verdict.** `console.py:79` should distinguish
   "0 detections out of 94 engines" from "no data". Suggest `virustotal_detections: [yellow]unavailable
   (429)[/]` when `data["errors"]["virustotal"]` is present, and a run-level banner counting targets with
   degraded coverage. This is a reporting change but it is caused by the concurrency defect, so it belongs
   in the same fix.

---

### F3 — Passing an explicit `transport=` silently disables HTTP/2 and discards `limits` and `verify`
**`tripper_recon/utils/http.py:41-51`** — severity **high**, fix is a one-line deletion

```python
def create_client(timeout: float = 15.0) -> httpx.AsyncClient:
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
    transport = httpx.AsyncHTTPTransport(retries=0)
    return httpx.AsyncClient(
        headers=default_headers(),
        http2=True,          # <- discarded
        timeout=httpx.Timeout(timeout),
        limits=limits,       # <- discarded
        transport=transport,
        verify=True,         # <- discarded
    )
```

`httpx.AsyncClient._init_transport` returns the supplied transport unchanged and never applies `http2`,
`limits`, `verify`, or `cert` to it:

```python
def _init_transport(self, verify=True, cert=None, trust_env=True,
                    http1=True, http2=False, limits=DEFAULT_LIMITS, transport=None):
    if transport is not None:
        return transport
    return AsyncHTTPTransport(verify=verify, cert=cert, trust_env=trust_env,
                              http1=http1, http2=http2, limits=limits)
```

`AsyncHTTPTransport(retries=0)` is built with defaults: `http2=False`, `limits=Limits(max_connections=100,
max_keepalive_connections=20, keepalive_expiry=5.0)`.

Verified against the installed httpx:

```
AS-WRITTEN  http2: False max_connections: 100 max_keepalive: 20
CONTROL     http2: True  max_connections: 50  max_keepalive: 20
```

So: HTTP/2 is off despite `http2=True`; the 50-connection cap you intended is actually 100. `README.md:23`
("Async & HTTP/2 First") is false as shipped.

Two further consequences worth naming:

- `retries=0` is already `AsyncHTTPTransport`'s default (verified from the signature). The transport line
  buys nothing at all and costs HTTP/2 plus the limits.
- The `if http2:` guard in `AsyncClient.__init__` still runs and still raises `ImportError` when `h2` is
  absent. So the tool hard-requires the `h2` dependency, pays for it in the install, and never uses it. I hit
  this directly: `ImportError: Using http2=True, but the 'h2' package is not installed.`

**Fix.** Delete the `transport=` argument.

```python
def create_client(timeout: float = 15.0, *, max_connections: int = 50) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers=default_headers(),
        http2=True,
        timeout=httpx.Timeout(connect=5.0, read=timeout, write=timeout, pool=timeout),
        limits=httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=20,
            keepalive_expiry=30.0,   # default 5.0 expires between bulk targets
        ),
        verify=True,
    )
```

---

### F4 — One `AsyncClient` per investigation destroys connection reuse on bulk input
**`tripper_recon/orchestrators.py:116`, `:203`, `:339`; `tripper_recon/cli.py:150-151`** — severity **high**

`investigate_ip` opens its own client (`orchestrators.py:116`). `cli.py:150-151` calls it once per target.
For N targets you get N independent connection pools with no shared keepalive.

Connection arithmetic for N = 200 (5 distinct provider hosts per target):

| | connections established |
|---|---|
| As written (N pools, HTTP/1.1, no sharing) | up to **N × 5 = 1,000** TCP+TLS handshakes |
| One shared client, HTTP/2 restored (F3) | ~**6** — one multiplexed connection per host |

At `H` ≈ 150 ms per handshake that is ~150 s of aggregate handshake work, and the Python-side TLS state
machines all run in the single event-loop thread even when the network waits overlap. I did not measure the
resulting wall-clock cost and will not invent one; the connection-count reduction from ~1,000 to ~6 is the
defensible claim.

(I checked the FD ceiling on this machine — `ulimit -n` is 1,048,576 — so file-descriptor exhaustion is
*not* a concern here. It would be on a stock 1024-FD host.)

**Fix.** Thread the client down, keeping a fallback so the FastAPI server (`api/server.py:25`) still works:

```python
# orchestrators.py
async def investigate_ip(ip: str, *, client: httpx.AsyncClient | None = None) -> InvestigationResult:
    if client is None:
        async with create_client() as owned:
            return await investigate_ip(ip, client=owned)
    ...   # existing body, no client creation
```

```python
# cli.py::_cmd_ip
async with create_client() as client:
    sem = asyncio.Semaphore(target_concurrency)          # created inside the running loop
    async def one(t: str):
        async with sem:
            return await investigate_ip(t, client=client)
    ...
```

For the API server, hold a single module-level client on FastAPI's `lifespan` rather than per request —
`api/server.py:23-44` currently pays a fresh pool per HTTP call, which is the same defect with a worse
duty cycle.

---

### F5 — `investigate_domain` awaits providers sequentially per IP, and IPs sequentially
**`tripper_recon/orchestrators.py:253-321`** — severity **high**

The domain-level pair is correct — `vt_domain_task` and `otx_domain_task` are created at
`orchestrators.py:204-205` and awaited at `:210` and `:217`, so they overlap. One wave.

Everything after that is serial. `for ip in ips:` (`:253`) runs one IP at a time, and inside it the five
providers are awaited one after another with no task creation at all:

```
:256  vt      = await vt_ip_summary(...)
:260  sh      = await shodan_host(...)
:264  ipi     = await ipinfo_ip(...)
:268  ab      = await abuseipdb_check(...)
:272  otx_ip  = await otx_ip_pulses(...)
:298  cf      = await fetch_asn_metadata(...)      # conditional
```

**Serial round-trip count:** `1 + K × 5` minimum, `1 + K × 7` when the Cloudflare Radar path runs and takes
its string fallback (F14). Note `investigate_ip` does the same five providers in **one** wave — the domain
path is 5× slower per IP than the IP path, for identical work.

At `R` = 400 ms, with a bounded restructure at concurrency 8 (waves = `1 + 2 × ceil(K / 8)`):

| K (IPs) | serial RTTs now | wall clock now | waves after fix | wall clock after | speed-up |
|---:|---:|---:|---:|---:|---:|
| 1 | 6 – 8 | 2.4 – 3.2 s | 3 | 1.2 s | 2 – 2.7× |
| 4 | 21 – 29 | 8.4 – 11.6 s | 3 | 1.2 s | 7 – 10× |
| 8 | 41 – 57 | 16.4 – 22.8 s | 3 | 1.2 s | 14 – 19× |
| 20 | 101 – 141 | 40.4 – 56.4 s | 7 | 2.8 s | 14 – 20× |

K = 8 to 20 is not exotic: `orchestrators.py:249` unions live DNS answers with every A/AAAA record VT has
ever seen (`:227-235`), so any CDN-fronted or fast-fluxing domain — exactly the ones an analyst is chasing —
lands in the high-K band. This is the single largest wall-clock defect in the tool.

**Restructure.** Hoist the loop body into a coroutine and gather it under a bound:

```python
async def _enrich_ip(client, keys, ip: str, sem: asyncio.Semaphore) -> Dict[str, Any]:
    async with sem:
        res = await _gather_providers(                 # helper from F10
            virustotal=vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip),
            shodan=shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip),
            ipinfo=ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip),
            abuseipdb=abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip),
            otx=otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip),
        )
        ipi = res["ipinfo"]
        if ipi.get("ok") and ipi["data"].get("asn"):
            res["cloudflare_asn"] = await _guard(
                fetch_asn_metadata(client=client, api_token=keys.cloudflare_api_token,
                                   asn=int(ipi["data"]["asn"]))
            )
    return res

# in investigate_domain, replacing :253-321
sem = asyncio.Semaphore(ip_concurrency)                # constructed inside the running loop — see F8
per_ip = await asyncio.gather(*(_enrich_ip(client, keys, ip, sem) for ip in ips))
```

The error-collection block (`:283-307`) and the `entry` dict (`:309-321`) then fold into a pure function over
`per_ip`, which also removes the `provider_errors` / `result_errors` mutation-inside-loop pattern.

**Sequencing caveat.** Parallelising this multiplies VT calls by K in the same instant. Ship F2's per-provider
budget in the same change, or this fix converts a slow domain lookup into an instant quota breach.

---

### F6 — No wall-clock deadline anywhere. A single hung provider can stall an investigation for minutes
**`tripper_recon/utils/http.py:47`, `tripper_recon/utils/backoff.py:18-27`, `tripper_recon/cli.py:151`** — severity **high**

`httpx.Timeout(15.0)` sets connect, read, write and pool all to 15 s. `with_exponential_backoff` makes
4 attempts with ~3.5–4.4 s of sleeping between them and no awareness of elapsed time.

Worst case per provider on a hung read: `4 × 15 s + 4.4 s ≈ **64 s**`. Worse if connect also stalls, since
httpx applies the phases separately.

| Path | worst case | output before then |
|---|---|---|
| `investigate_ip`, single target (5 concurrent) | ~64 s | none |
| `investigate_domain`, K = 8 (serial, F5) | 8 × 5 × 64 s ≈ **43 min** | none |
| `investigate_domain`, K = 8, after F5 fix | ~64 s | none |

`_cmd_domain` (`cli.py:208`) awaits the whole investigation before printing anything, so the analyst stares
at a blank terminal for the full duration with no indication of progress or of which provider is hanging.

**Fix.**
- Split the timeout: `connect=5.0` (a dead host should fail in 5 s), `read=15.0`. Already in the F3 snippet.
- Give the backoff a deadline, not just an attempt count:
  ```python
  async def with_exponential_backoff(fn, *, retries=3, base_delay=0.5,
                                     max_delay=5.0, deadline: float = 20.0):
      started = time.monotonic()
      ...
      if time.monotonic() - started + delay > deadline:
          break
  ```
- Give each target a hard budget in the CLI. `pyproject.toml:9` declares `requires-python = ">=3.10"`, so
  `asyncio.timeout` (3.11+) is not available — use `asyncio.wait_for`:
  ```python
  res = await asyncio.wait_for(investigate_ip(t, client=client), timeout=per_target_budget)
  ```
  and surface the timeout as a per-provider `error` payload rather than a dropped target. See F12 —
  `wait_for` cancellation is exactly what makes that latent bug reachable.

---

### F7 — Bulk output is withheld until the slowest target completes
**`tripper_recon/cli.py:150-186`** — severity **medium**

```python
tasks = [investigate_ip(t) for t in targets]
gathered = await asyncio.gather(*tasks, return_exceptions=True)
for target, item in zip(targets, gathered):
    ...   # rendering starts here
```

`asyncio.gather` returns only when every coroutine has finished. Time-to-first-answer equals
time-to-last-answer. One target that trips the 64 s worst case (F6) blocks the console output for 199
already-complete targets. For a tool sold on "speed to answer", this is the perceived-latency defect even
when the aggregate throughput is fine.

**Fix.** Stream results as they land, and keep deterministic ordering by rendering into a pre-sized slot
list, or accept arrival order for `console` output and preserve input order only for `json`:

```python
async def one(idx: int, t: str):
    async with sem:
        return idx, t, await investigate_ip(t, client=client)

pending = {asyncio.create_task(one(i, t)) for i, t in enumerate(targets)}
for fut in asyncio.as_completed(pending):
    idx, t, res = await fut
    if output == "console":
        console.print(render_ip_analysis(t, res.data, ports_limit=ports_limit))
    results[idx] = res
```

Pair this with a `rich.progress` counter — with 200 targets in flight the analyst currently has no idea
whether the tool is working or wedged.

---

### F8 — The module-level `_global_sem` binds to the first event loop that blocks on it
**`tripper_recon/utils/http.py:54-66`** — severity **medium** now, **high as a fix-ordering hazard**

```python
_global_sem: asyncio.Semaphore | None = None

class RateLimiter:
    def __init__(self, rate: int | None = None):
        global _global_sem
        if _global_sem is None:
            _global_sem = asyncio.Semaphore(rate if rate is not None else _init_rate)
        self._sem = _global_sem
```

Since Python 3.10, `asyncio.Semaphore` binds lazily via `_LoopBoundMixin._get_loop()` — the binding happens
the first time the semaphore actually *waits*, not at construction. A process-global semaphore therefore
survives one `asyncio.run` and then fails on a later one. Verified:

```
PROBE3 asyncio.run #2 (contended): OK
PROBE3 asyncio.run #3 (contended): RuntimeError: <asyncio.locks.Semaphore ... [locked]>
                                    is bound to a different event loop
```

Note the shape of the failure: run #2 succeeded (it was the first to contend, so it did the binding) and
run #3 raised. Intermittent, loop-dependent, and it looks like a heisenbug.

This is dormant today **only because F1 means the semaphore never blocks.** Fix F1 without fixing this and
the tool starts raising `RuntimeError` in any process that calls `asyncio.run` more than once — test suites,
scripts driving `investigate_ip` in a loop, and any future `--watch` mode. `cli.py:421/423/435` each call
`asyncio.run` on a mutually exclusive branch, so today's CLI is safe by accident.

**Fix.** No module-global synchronisation primitives. Build the limiter set once per investigation inside
the running loop and pass it down, or key a registry on `asyncio.get_running_loop()`:

```python
_LIMITERS: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, ProviderLimiter]]" = \
    weakref.WeakKeyDictionary()

def limiters() -> dict[str, ProviderLimiter]:
    loop = asyncio.get_running_loop()
    if loop not in _LIMITERS:
        _LIMITERS[loop] = {name: ProviderLimiter(spec) for name, spec in PROVIDER_LIMITS.items()}
    return _LIMITERS[loop]
```

The same rule applies to the F5 `ip_concurrency` semaphore and to anything F2 adds.

---

### F9 — `investigate_asn` runs two serial waves where one would do
**`tripper_recon/orchestrators.py:341-397`** — severity **medium**

Wave 1 creates seven tasks (`:341-353`) and awaits all of them (`:355-381`). Only then does `:383-385`
create `routing_status`, `asn_neighbours` and `announced_prefixes` — three RIPEstat calls that have no
dependency on wave 1 and could have been created alongside it. `cf_task` is created in wave 1 and awaited in
wave 2, which is fine.

Cost: one extra serial RTT, ~200–600 ms for RIPEstat, on every `tripper-recon asn` invocation. Fix is to
move lines 383-385 up to sit with 341-345, which the F10 helper does naturally.

A second, larger item on the same path: `--neighbors` defaults to 8 (`cli.py:402`), so `:493-501` fires up to
24 additional RIPEstat `as-overview` calls, unbounded, in one `gather`. That is a burst against a public
service that asks callers to identify themselves via `sourceapp` (`ripestat.py:26`). Bound it.

Minor, not a bug today: `:500-502` zips a `list` comprehension over a `set` with `gather`'s results. Both
iterate the same unmutated `set` object, so the pairing is deterministic and correct — but it is one edit
away from silently mislabelling ASN → name. Materialise `to_resolve = sorted(to_resolve)` first.

---

### F10 — 23 duplicated `try / await / except` blocks; one helper removes them without losing error payloads
**`tripper_recon/orchestrators.py:132-151`, `:209-219`, `:255-274`, `:297-300`, `:355-402`** — severity **medium**

Block count: `investigate_ip` 5 (`:132-151`), `investigate_domain` 8 (`:209-219`, `:255-274`, `:297-300`),
`investigate_asn` 10 (`:355-379`, `:386-402`). Twenty-three blocks, ~92 lines, all identical modulo the
variable name. Every one of them serialises what could be concurrent — the duplication and the latency
defect are the same defect.

```python
from typing import Awaitable

async def _guard(coro: Awaitable[Dict[str, Any]]) -> Dict[str, Any]:
    """Await a provider coroutine, converting failures into the standard error payload."""
    try:
        return await coro
    except asyncio.CancelledError:
        raise                              # cancellation is control flow, never a provider error
    except Exception as e:                 # noqa: BLE001
        return _error_payload(e)

async def _gather_providers(**coros: Awaitable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Run named provider coroutines concurrently; return {name: payload}. Never raises."""
    names = list(coros)
    values = await asyncio.gather(*(_guard(c) for c in coros.values()))
    return dict(zip(names, values))
```

Call sites collapse to:

```python
res = await _gather_providers(
    virustotal=vt_ip_summary(client=client, api_key=keys.vt_api_key, ip=ip),
    ipinfo=ipinfo_ip(client=client, token=keys.ipinfo_token, ip=ip),
    shodan=shodan_host(client=client, api_key=keys.shodan_api_key, ip=ip),
    abuseipdb=abuseipdb_check(client=client, api_key=keys.abuseipdb_api_key, ip=ip),
    otx=otx_ip_pulses(client=client, api_key=keys.otx_api_key, ip=ip),
)
```

Four properties worth stating, because they are the reasons this is safe:

1. **Per-provider payloads are preserved exactly.** `_error_payload` still runs per coroutine, so the
   `http_error` / `network_error` / status / reason / url discrimination at `:29-49` is untouched, and so are
   `_should_suppress` and `_error_summary`.
2. **Do not use `gather(..., return_exceptions=True)` here.** `_guard` already converts, and
   `return_exceptions=True` would additionally capture `CancelledError` (a `BaseException`) as a *result* —
   which is precisely the bug in F12.
3. **Conditional providers** (VT/OTX only when a key is present, `:204-205`; Cloudflare only with a token,
   `:348-353`) must be assembled into a dict before splatting, so an unused coroutine is never created —
   otherwise Python emits `RuntimeWarning: coroutine ... was never awaited`:
   ```python
   calls: dict[str, Awaitable[Dict[str, Any]]] = {"ipinfo_asn": ipinfo_asn(...), "ripe_overview": ...}
   if keys.cloudflare_api_token:
       calls["cloudflare_asn"] = fetch_asn_metadata(...)
   res = await _gather_providers(**calls)
   ```
4. **Ordering is preserved.** `dict` and `gather` both preserve argument order, so `dict(zip(names, values))`
   pairs correctly without relying on set iteration.

---

### F11 — Non-retryable 4xx responses are retried 4×, costing ~3.5 s per provider per target
**`tripper_recon/utils/backoff.py:18-27`; `virustotal.py:22`, `shodan_api.py:21`, `abuseipdb.py:25`, `ipinfo.py:19`, `otx.py:22`, `otx.py:45`** — severity **medium**

`with_exponential_backoff` retries on bare `Exception`. `r.raise_for_status()` raises on 401 and 403 as
readily as on 503. An expired or wrong API key therefore costs 4 requests and ~3.5 s of `asyncio.sleep`
per provider per target, for an outcome that cannot change. On a 200-target bulk run with one bad key that
is 800 wasted requests and ~3.5 s added to every target's critical path.

The behaviour is also inconsistent across providers: `caida.py:18-19`, `ripestat.py:18-19`,
`peeringdb.py:17-18` and both Cloudflare modules return a dict on `>= 400` instead of raising, so they never
retry — including on genuinely transient 502/503. The retry policy is decided by an accident of each
provider's error style rather than by the status code.

**Fix.** Classify centrally, and honour `Retry-After`:

```python
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}

def _retry_after(exc: Exception) -> float | None:
    resp = getattr(exc, "response", None)
    if resp is None:
        return None
    raw = resp.headers.get("retry-after")
    ...   # seconds, or HTTP-date

# in the except branch:
if isinstance(e, httpx.HTTPStatusError) and e.response.status_code not in RETRYABLE_STATUS:
    raise
delay = _retry_after(e) or min(max_delay, base_delay * (2 ** attempt))
```

Then make the provider modules consistent: raise on `>= 400` everywhere and let the policy decide, rather
than half of them swallowing errors into dicts.

---

### F12 — A cancelled child is misclassified in `_cmd_ip` and crashes the result loop
**`tripper_recon/cli.py:151`, `:158`, `:169-171`** — severity **low** today, **reachable the moment F6 lands**

```python
gathered = await asyncio.gather(*tasks, return_exceptions=True)
for target, item in zip(targets, gathered):
    if isinstance(item, Exception):
        ...   # handled
        continue
    res = item
    if not res.ok:      # <- AttributeError if item is a CancelledError
```

`asyncio.CancelledError` inherits from `BaseException`, not `Exception`, since Python 3.8. With
`return_exceptions=True`, a cancelled child's `CancelledError` is returned as a *result*. Verified:

```
 item: CancelledError isinstance(Exception) = False isinstance(BaseException) = True
  -> AttributeError: 'CancelledError' object has no attribute 'ok'
```

Nothing in the current code cancels an individual child, so this is latent. It becomes live as soon as F6
wraps each target in `asyncio.wait_for`, or F7 introduces per-target cancellation. I did **not** verify the
Ctrl-C path — a `KeyboardInterrupt` during `asyncio.run` cancels the outer gather, which re-raises rather
than returning results, so I believe Ctrl-C does not hit this today. What would settle it: run
`tripper-recon ip <file>` against a mock HTTP server and send SIGINT mid-run.

**Fix.** `if isinstance(item, BaseException):` — and re-raise `CancelledError` rather than reporting it as a
target failure, so Ctrl-C exits cleanly instead of printing 200 error panels.

---

### F13 — `resolve_domain` has no timeout and serialises A then AAAA in one thread
**`tripper_recon/utils/dns.py:8-23`, called at `tripper_recon/orchestrators.py:247-248`** — severity **medium**

```python
for family in (socket.AF_INET, socket.AF_INET6):
    infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
```

Two blocking `getaddrinfo` calls run back-to-back inside a single `asyncio.to_thread`. There is no
`asyncio.wait_for` around it, so the stall is bounded only by the system resolver — glibc's default
`timeout:5 attempts:2` per `nameserver` means a sinkholed or non-responding domain can hang this for tens of
seconds, and it is on the critical path before any IP enrichment starts (`:249`). `asyncio.to_thread` cannot
be cancelled, so even a `wait_for` around the call leaks the thread until the resolver gives up.

**Fix.** Issue both families concurrently (`asyncio.gather` over two `to_thread` calls), wrap in
`asyncio.wait_for(..., timeout=3.0)`, and treat a timeout as "no active IPs" while still proceeding with the
VT passive-DNS IPs already collected at `:227-235`.

**Out of my lane but flagged:** `resolve_domain` queries the system resolver for the target domain. Under the
passive-only constraint that is the grey area the brief names, and `reverse_ptr` (`dns.py:26-34`) is the same
class of call. The security lens should rule on whether either is permitted; my concern here is only that
it is an unbounded blocking call on the hot path.

Related dead code: `entry["ptr"]` is populated from `ptr = None` (`orchestrators.py:254`) and never assigned
again, so `ptr` is always `null` in every domain result. `reverse_ptr` has no callers.

---

### F14 — Cloudflare Radar's int→string fallback costs a full second backoff cycle before it retries
**`tripper_recon/providers/cloudflare_radar.py:73-78`** — severity **low**

```python
res = await with_exponential_backoff(_call_int)
if res.get("ok"):
    return res
res2 = await with_exponential_backoff(_call_str)
return res2
```

`_call_int` returns a dict on non-200 rather than raising (`:38-39`), so the backoff never retries it — but
if the Int-typed query is the wrong schema for this endpoint, every ASN lookup pays two serial round trips.
When `_call_int` raises for a network reason, the sequence is up to 4 attempts + ~4 s of sleeping, *then*
4 more attempts of `_call_str` — up to 8 requests and ~8 s for one metadata field, serialised.

**Fix.** Probe the schema once per process and cache the winner, or drop the Int variant if the string form
is known to work. `_should_suppress` (`orchestrators.py:82-86`) already treats a Cloudflare 400 as expected
noise, which suggests the Int query is routinely wrong.

---

### F15 — `peeringdb` performs 1 + N serial GETs inside a retried closure
**`tripper_recon/providers/peeringdb.py:14-41`** — severity **low**

The `_call` closure does one `GET /net` (`:16`) then one `GET /net/{id}` per result (`:27`), serially, and the
whole closure is wrapped in `with_exponential_backoff` (`:41`). A failure on the last sub-request replays
every earlier one, and PeeringDB is unauthenticated here so it is the most likely provider to rate-limit.

**Fix.** Gather the `/net/{id}` calls concurrently under a small bound, and move the retry to the individual
request rather than the whole sequence.

---

## Suggested fix order

The dependencies between these matter; done in the wrong order, two of them make things worse.

1. **F3** — delete the `transport=` argument. One line, restores HTTP/2 and the intended limits, zero risk.
2. **F2** — per-provider token buckets + `Retry-After` + F11's status classification. **Must land before F1
   and F5**, or fixing the concurrency makes the quota breach faster.
3. **F8** — make all limiters loop-local. **Must land with or before F1**, or F1 detonates the cross-loop
   `RuntimeError`.
4. **F1** — hold the limiter around the await.
5. **F10** — the `_guard` / `_gather_providers` helper. Pure refactor, and it is the vehicle for the next two.
6. **F5** — restructure `investigate_domain`'s per-IP loop. Largest single wall-clock win.
7. **F4** + **F7** — share one client across a bulk run and stream results.
8. **F6** + **F13** — deadlines everywhere, then **F12** becomes reachable and must be fixed in the same change.
9. **F9**, **F14**, **F15** — cheap cleanups.

## Documentation corrections implied by the above

- `README.md:23` — "Async & HTTP/2 First" is false as shipped (F3).
- `README.md:24` — "handling rate limits (429 Too Many Requests) elegantly" describes behaviour that does
  not exist; the tool retries 429s blindly and ignores `Retry-After` (F2, F11).
- `cli.py:383` — `--rate-limit` help text promises a cap that is never applied (F1). Either wire it up or
  remove the flag; a flag that silently does nothing is worse than no flag.

## What I did not verify

- Any provider's actual published rate limit or daily quota. VT 4/min-500/day and AbuseIPDB's daily cap are
  repeated from the task brief and carry `[unverified]`. Pull the vendor docs before hard-coding
  `PROVIDER_LIMITS`.
- Real-world provider RTTs. Every millisecond figure is `R` = 400 ms substituted into a round-trip count.
  The round-trip counts are read off the code and are the load-bearing part.
- The Ctrl-C path in F12 (latent-vs-live). Settling it needs a mock server and a SIGINT.
- Whether `h2` is installed in the environment the operator actually runs the tool in. It is absent from the
  interpreter I probed with, which would make `create_client` raise `ImportError` on every invocation there.
