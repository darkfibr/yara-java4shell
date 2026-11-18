# yara-java4shell

YARA memory-forensics rules for **Java4Shell (CVE-2026-114938)** — the AVX-512 VBMI
Base64 decoder heap overflow in OpenJDK (Java 17, 21, 25, 27).

The disclosure repo (calif.io crew) ships Suricata/Sigma/ModSecurity for the **wire**.
Nobody covered **memory**. This is that layer: JVM heap dumps, hprof files, raw memory
images — for DFIR teams scanning compromised hosts.

## Rules

| rule | tier | match |
|---|---|---|
| `JAVA4SHELL_Heap_Overflow_Triplet` | high confidence | cyclic `69 A6 9A` triplet (any rotation) x3+ — the constant-value vector store |
| `JAVA4SHELL_Heap_Overflow_Loose` | triage | triplet x2 any rotation, or `9A`-saturation run (>=12) for groomed/partial heaps |

## Validation

Reproduced in a local lab the night of disclosure (2026-11-17): pre-fix OpenJDK
**21.0.12.1+1** on an AVX-512 VBMI2 host, Phase-1-only overflow proof (warm the
intrinsic, decode `"A"*64 + "="` into an oversized buffer, capture the 62 bytes
written past decodedLen). Both rules fire on the capture; no false positives on
benign binaries in control scans.

**Ground truth from the capture** (note the rotation — rules match all three phases):

```
+00: 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a
...cyclic triplet...
+46: ...degrades to pure 9a runs (lookup-tail saturation)
```

## Files

- `java4shell.yar` — the rules
- `OverflowProof.java` — safe standalone repro (Phase 1 only: no spray, no feng-shui,
  oversized buffer catches the store in-bounds; single process, own heap)
- `overflow_capture.bin` — 512-byte lab capture for testing your YARA deployment

## Trigger reference (from the disclosure)

- JDK 21+: `"A" * 64 + "="`
- JDK 17: `"A" * 128 + "="`
- Malformed shape: dangling single `=`; input length % 4 == 1
- Mitigation on x86 until patched: `-XX:UseAVX=2` (do not set on ARM64 — JVM refuses to start)

## Sources

- Disclosure: https://calif.io/java4shell
- PoC + wire detection: https://github.com/ikow/java4shell-poc

## License

MIT. Detection rules are for defenders; use freely.
