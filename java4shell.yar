/*
    YARA — Java4Shell (CVE-2026-114938) memory-forensics rules v1.0
    House: phoenix / DarkFibre — 2026-11-17/18, night of disclosure.

    VALIDATED against live corruption reproduced in our own lab
    (pre-fix OpenJDK 21.0.12.1+1, AVX-512 VBMI2 host, Phase-1-only
    overflow proof; capture: overflow_capture.bin):

        +00: 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a 69 a6 9a
        ...  (cyclic triplet, ANY ROTATION: 69 A6 9A / A6 9A 69 / 9A 69 A6)
        +46: ...degrades to a run of pure 9A (lookup-tail saturation)

    The overflow: malformed Base64 ("A"*64 + "=" on JDK 21+; "A"*128 + "="
    on JDK 17 — dangling single '=', input length % 4 == 1) drives the
    AVX-512 VBMI decode intrinsic's vector store 62 bytes past the decoded
    length inside the destination byte[]. On wire: see the calif.io crew's
    Suricata/Sigma set (github.com/ikow/java4shell-poc) — this file is the
    MEMORY layer they don't cover: heap dumps, hprof, raw memory images.

    v0.1 -> v1.0: v0.1 anchored only the {69 A6 9A} rotation and would
    MISS phase-shifted dumps (our own capture starts 9A 69 A6). v1.0
    matches all three rotations plus the 9A-saturation tail.

    — Lyra (GLM-5.3, the Huntress), validated at 21:20 ET 2026-11-17
*/

rule JAVA4SHELL_Heap_Overflow_Triplet
{
    meta:
        family      = "JAVA4SHELL"
        cve         = "CVE-2026-114938"
        severity    = "critical"
        author      = "darkfibre / lyra"
        date        = "2026-11-18"
        description = "Cyclic 69/A6/9A triplet overflow from AVX-512 VBMI Base64 decode OOB write (any rotation, >=3 triplets)"
        reference   = "https://calif.io/java4shell"
        scope       = "JVM heap dumps, hprof, memory images"
        validation  = "lab-reproduced, capture overflow_capture.bin"

    strings:
        $r0 = { 69 A6 9A 69 A6 9A 69 A6 9A }
        $r1 = { A6 9A 69 A6 9A 69 A6 9A 69 }
        $r2 = { 9A 69 A6 9A 69 A6 9A 69 A6 }

    condition:
        any of them
}

rule JAVA4SHELL_Heap_Overflow_Loose
{
    meta:
        family      = "JAVA4SHELL"
        cve         = "CVE-2026-114938"
        severity    = "high"
        author      = "darkfibre / lyra"
        date        = "2026-11-18"
        description = "Triage tier: triplet x2 at any rotation, OR 9A-saturation run (>=12) — catches groomed/partial heaps"
        note        = "9A-run alone can false-positive on exotic compressed data; confirm with the triplet rule or context"

    strings:
        $t0 = { 69 A6 9A 69 A6 9A }
        $t1 = { A6 9A 69 A6 9A 69 }
        $t2 = { 9A 69 A6 9A 69 A6 }
        $sat = { 9A 9A 9A 9A 9A 9A 9A 9A 9A 9A 9A 9A }

    condition:
        any of ($t*) or $sat
}
