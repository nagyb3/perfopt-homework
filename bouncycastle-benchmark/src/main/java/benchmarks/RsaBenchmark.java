package benchmarks;

import org.openjdk.jmh.annotations.*;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 20)
@Measurement(iterations = 10)
public class RsaBenchmark {

	private static final int KEY_SIZE = 2048;
	private static final int DATA_SIZE = 32;
	private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	private byte[] plaintext;
	private byte[] ciphertext;
	private Cipher encryptCipher;
	private Cipher decryptCipher;

	@Setup(Level.Trial)
	public void setup() throws Exception {
		BouncyCastleProviderUtil.ensureRegistered();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(KEY_SIZE, new SecureRandom());
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		encryptCipher = Cipher.getInstance(ALGORITHM, "BC");
		decryptCipher = Cipher.getInstance(ALGORITHM, "BC");
		encryptCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic(), new SecureRandom());
		decryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), new SecureRandom());

		plaintext = new byte[DATA_SIZE];
		new SecureRandom().nextBytes(plaintext);

		ciphertext = encryptCipher.doFinal(plaintext);

		byte[] roundTrip = decryptCipher.doFinal(ciphertext);
		if (!Arrays.equals(plaintext, roundTrip)) {
			throw new IllegalStateException("RSA setup verification failed");
		}
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