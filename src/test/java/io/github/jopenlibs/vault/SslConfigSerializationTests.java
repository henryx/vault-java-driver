package io.github.jopenlibs.vault;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests verifying that SSL settings survive Java serialization.
 */
public class SslConfigSerializationTests {

    @SuppressWarnings("unchecked")
    private static <T> T roundTrip(final T object) throws IOException, ClassNotFoundException {
        final var bytes = new ByteArrayOutputStream();
        try (var out = new ObjectOutputStream(bytes)) {
            out.writeObject(object);
        }
        try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return (T) in.readObject();
        }
    }

    private static String certPem() throws IOException {
        try (var input = SslConfigSerializationTests.class.getResourceAsStream("/cert.pem")) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    public void testVerifyEnabledSurvives() throws Exception {
        assertTrue(roundTrip(new SslConfig().verify(true).build()).isVerify());
    }

    @Test
    public void testVerifyDisabledSurvives() throws Exception {
        assertFalse(roundTrip(new SslConfig().verify(false).build()).isVerify());
    }

    @Test
    public void testPemCertificateSurvives() throws Exception {
        final String pem = certPem();
        final var copy = roundTrip(new SslConfig().pemUTF8(pem).build());

        assertEquals(pem, copy.getPemUTF8());
        assertNotNull(copy.getSslContext());
    }

    /**
     * A deserialized, already built <code>SslConfig</code> is not rebuilt by
     * <code>VaultConfig.build()</code>.
     */
    @Test
    public void testBuiltStateSurvives() throws Exception {
        final var copy = roundTrip(new SslConfig().pemUTF8(certPem()).build());
        final var sslContext = copy.getSslContext();

        new VaultConfig().address("https://127.0.0.1:8200").sslConfig(copy).build();
        assertSame(sslContext, copy.getSslContext());
    }

    @Test
    public void testVaultConfigSslSettingsSurvive() throws Exception {
        final var config = new VaultConfig()
                .address("https://127.0.0.1:8200")
                .sslConfig(new SslConfig().pemUTF8(certPem()))
                .build();
        final var copy = roundTrip(config);

        assertTrue(copy.getSslConfig().isVerify());
        assertNotNull(copy.getSslConfig().getSslContext());
    }
}
