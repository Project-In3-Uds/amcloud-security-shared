package cm.amcloud.platform.amcloud_security_shared;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        // Initialise le JwtUtil avec la clé publique
        jwtUtil = new JwtUtil(publicKey);
    }

    @Test
    void shouldValidateAndExtractUsernameFromValidToken() {
        String username = "testuser";
        String token = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60_000)) // 1 min
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        assertTrue(jwtUtil.isTokenValid(token));
        assertEquals(username, jwtUtil.extractUsername(token));
    }

    @Test
    void shouldRejectInvalidToken() {
        String invalidToken = "invalid.token.value";
        assertFalse(jwtUtil.isTokenValid(invalidToken));
    }

    // Helper method to load private key (not strictly needed if using KeyPair)
    private PrivateKey loadPrivateKey(String path) throws Exception {
        var resource = new ClassPathResource(path);
        String key = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    // Helper method to load public key (not strictly needed if using KeyPair)
    private PublicKey loadPublicKey(String path) throws Exception {
        var resource = new ClassPathResource(path);
        String key = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}