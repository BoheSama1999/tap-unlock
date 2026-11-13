package xyz.bohesama.tapunlock;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class Protocol {
    static final int COMPANY_ID = 0xFFFF;
    static final byte VERSION = 0x01;
    static final byte TYPE_CHALLENGE = 0x01;
    static final byte TYPE_RESPONSE = 0x02;
    static final int NONCE_LEN = 16;
    static final int HINT_LEN = 4;
    static final byte[] CHALLENGE_PREFIX = {'N', 'K', VERSION, TYPE_CHALLENGE};
    static final byte[] CHALLENGE_MASK = {-1, -1, -1, -1};
    private static final byte[] CONTEXT = "tap-unlock/v1\0".getBytes(StandardCharsets.US_ASCII);

    private Protocol() {}

    static byte[] nonceFromChallenge(byte[] data) {
        if (data == null || data.length != CHALLENGE_PREFIX.length + NONCE_LEN) return null;
        if (!Arrays.equals(Arrays.copyOf(data, CHALLENGE_PREFIX.length), CHALLENGE_PREFIX)) return null;
        return Arrays.copyOfRange(data, CHALLENGE_PREFIX.length, data.length);
    }

    static byte[] signedMessage(byte[] nonce) {
        byte[] message = Arrays.copyOf(CONTEXT, CONTEXT.length + nonce.length);
        System.arraycopy(nonce, 0, message, CONTEXT.length, nonce.length);
        return message;
    }

    static byte[] response(byte[] nonce, byte[] derSignature) {
        byte[] out = new byte[4 + HINT_LEN + derSignature.length];
        out[0] = 'N';
        out[1] = 'K';
        out[2] = VERSION;
        out[3] = TYPE_RESPONSE;
        System.arraycopy(nonce, 0, out, 4, HINT_LEN);
        System.arraycopy(derSignature, 0, out, 4 + HINT_LEN, derSignature.length);
        return out;
    }
}
