The six libFuzzer targets exercise raw and authenticated protocol boundaries,
with AddressSanitizer and UndefinedBehaviorSanitizer enabled. Run a bounded
campaign from the repository root:

```sh
python3 tools/check_fuzz.py --seconds 30
```

The runner requires Clang's libFuzzer runtime and OpenSSL development headers.
It builds outside the library's normal CMake configuration, generates a seed
corpus and dictionary, and writes per-target logs plus `summary.json` into
`build-fuzz/`. Pass `--targets json policy` to select targets, `--jobs 2` to
bound concurrency, or `--runs 100000` for a deterministic iteration bound.
Mutations use a fixed seed by default; override it with `--seed`.

Crashes and timeouts are retained under each target's `artifacts/` directory.
The runner fails if compilation or any campaign fails. Reproduce a crash with
`build-fuzz/<target>/fuzz-<target> <artifact-path>`. It does not claim security
certification: campaigns are bounded and coverage-guided, and system crypto
libraries themselves are not sanitizer-instrumented by this build.

The packet target checks encode/decode round trips, overlapping payloads,
checksums and unchanged outputs on failure. STUN exercises raw messages and
valid outer framing with arbitrary attributes. JSON checks token structure,
Unicode string decoding, integer conversion and storage exhaustion. Policy
checks deny-all on every parse failure. DERP exercises HTTP upgrade, stream
fragmentation, bounded output backpressure, sticky errors, and authenticated
server-info JSON. DISCO tests raw and authenticated discovery messages,
bounded endpoint sets, relay restrictions and one-time pong transactions.
