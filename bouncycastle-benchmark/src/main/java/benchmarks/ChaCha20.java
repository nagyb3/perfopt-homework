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
@Warmup(iterations = 5)
@Measurement(iterations = 10)
public class ChaCha20 {

    private static final int DATA_SIZE = 1024;
    private static final String ALGORITHM = "ChaCha7539";

    private byte[] plaintext;
    private byte[] ciphertext;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        BouncyCastleProviderUtil.ensureRegistered();

        SecureRandom secureRandom = new SecureRandom();

        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(key);
        secureRandom.nextBytes(nonce);

        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(nonce);

        encryptCipher = Cipher.getInstance(ALGORITHM, "BC");
        decryptCipher = Cipher.getInstance(ALGORITHM, "BC");
        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        plaintext = new byte[DATA_SIZE];
        secureRandom.nextBytes(plaintext);

        ciphertext = encryptCipher.doFinal(plaintext);
        byte[] roundTrip = decryptCipher.doFinal(ciphertext);
        if (!Arrays.equals(plaintext, roundTrip)) {
            throw new IllegalStateException("ChaCha20 setup verification failed");
        }

        encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    }

    @Benchmark
    public byte[] encrypt() throws Exception {
        return encryptCipher.doFinal(plaintext);
    }

    @Benchmark
    public byte[] decrypt() throws Exception {
        return decryptCipher.doFinal(ciphertext);
    }
}