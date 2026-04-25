package benchmarks;

import java.security.Security;

public final class BouncyCastleProviderUtil {

    private BouncyCastleProviderUtil() {
    }

    public static void ensureRegistered() {
        if (Security.getProvider("BC") != null) {
            return;
        }
        try {
            Class<?> providerClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Security.addProvider((java.security.Provider) providerClass.getDeclaredConstructor().newInstance());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Bouncy Castle provider is missing from classpath", e);
        }
    }
}

