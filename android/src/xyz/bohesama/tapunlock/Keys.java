package xyz.bohesama.tapunlock;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.io.IOException;

final class Keys {
    private static final String ALIAS = "tap-unlock-v1";

    private Keys() {}

    private static KeyStore store() throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        return ks;
    }

    static PublicKey ensure() throws GeneralSecurityException, IOException {
        KeyStore ks = store();
        if (!ks.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUnlockedDeviceRequired(true)
                    .build());
            generator.generateKeyPair();
        }
        return ks.getCertificate(ALIAS).getPublicKey();
    }

    static byte[] sign(byte[] message) throws GeneralSecurityException, IOException {
        PrivateKey key = (PrivateKey) store().getKey(ALIAS, null);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        signature.update(message);
        return signature.sign();
    }

    static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
                + Base64.encodeToString(key.getEncoded(), Base64.DEFAULT)
                + "-----END PUBLIC KEY-----\n";
    }
}
