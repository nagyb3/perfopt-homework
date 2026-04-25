package benchmarks;

import org.openjdk.jmh.annotations.*;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(3)
public class Sha256Benchmark {

    private static final int DATA_SIZE = 1024;

    private byte[] data;
    private MessageDigest digest;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        BouncyCastleProviderUtil.ensureRegistered();
        data = new byte[DATA_SIZE];
        new SecureRandom().nextBytes(data);
        digest = MessageDigest.getInstance("SHA-256", "BC");
    }

    @Benchmark
    public byte[] sha256() {
        return digest.digest(data);
    }
}