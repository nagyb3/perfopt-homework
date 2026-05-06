package benchmarks;

import org.openjdk.jmh.annotations.*;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 20, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 10, time = 1, timeUnit = TimeUnit.SECONDS)
public class ChaCha20 {

    private static final int DATA_SIZE = 1024;
    private static final String ALGORITHM = "ChaCha20-Poly1305";

    private byte[] plaintext;
    private byte[] ciphertext;
    private byte[] staticNonce;

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    private long counter = 0;
    private SecretKeySpec keySpec;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        BouncyCastleProviderUtil.ensureRegistered();

        SecureRandom secureRandom = new SecureRandom();

        byte[] key = new byte[32];
        this.staticNonce = new byte[12];
        secureRandom.nextBytes(key);
        secureRandom.nextBytes(staticNonce);

        this.keySpec = new SecretKeySpec(key, ALGORITHM);
        this.plaintext = new byte[DATA_SIZE];
        secureRandom.nextBytes(plaintext);

        this.encryptCipher = Cipher.getInstance(ALGORITHM, "BC");
        this.decryptCipher = Cipher.getInstance(ALGORITHM, "BC");

        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(staticNonce));
        this.ciphertext = encryptCipher.doFinal(plaintext);

        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(staticNonce));
        byte[] roundTrip = decryptCipher.doFinal(ciphertext);

        if (!Arrays.equals(plaintext, roundTrip)) {
            throw new IllegalStateException("ChaCha20 setup verification failed");
        }
    }

    private byte[] nextNonce() {
        byte[] nonce = new byte[12];
        for (int i = 0; i < 8; i++) {
            nonce[11 - i] = (byte) (counter >>> (8 * i));
        }
        counter++;
        return nonce;
    }

    @Benchmark
    public byte[] encrypt() throws Exception {
        byte[] nonce = nextNonce();
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
        return encryptCipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] decrypt() throws Exception {
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(staticNonce));
        return decryptCipher.doFinal(ciphertext);
    }
}