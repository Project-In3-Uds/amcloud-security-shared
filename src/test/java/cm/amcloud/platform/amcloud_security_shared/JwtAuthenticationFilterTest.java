package cm.amcloud.platform.amcloud_security_shared;

import java.security.KeyPair;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;

public class JwtAuthenticationFilterTest {

    private JwtUtil jwtUtil;
    private JwtAuthenticationFilter filter;
    private KeyPair keyPair;

    @BeforeEach
    public void setup() throws Exception {
        keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
        jwtUtil = new JwtUtil(keyPair.getPublic()); // Pass the PublicKey to the constructor
        filter = new JwtAuthenticationFilter(jwtUtil);
    }

    @Test
    public void shouldAuthenticateWithValidToken() throws Exception {
        // Génère un token avec la clé privée
        String token = Jwts.builder()
                .setSubject("testuser")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();

        // Prépare la requête avec le token
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = (req, res) -> {}; // no-op

        // Exécute le filtre
        filter.doFilterInternal(request, response, filterChain);

        // Vérifie que l’utilisateur est bien authentifié
        assertNotNull(SecurityContextHolder.getContext().getAuthentication(), "Authentication should not be null");
        assertEquals("testuser", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

    @Test
    public void shouldSkipAuthenticationIfNoToken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        filter.doFilterInternal(request, response, filterChain);

        // Ensure the filter chain proceeds (authentication is skipped)
        verify(filterChain, times(1)).doFilter(request, response);
        assertNull(SecurityContextHolder.getContext().getAuthentication(), "Authentication should be null");
    }

    @Test
    public void shouldNotAuthenticateWithInvalidToken() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid.token");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain filterChain = Mockito.mock(FilterChain.class);

        filter.doFilterInternal(request, response, filterChain);

        // Authentication should remain null, and the filter chain should proceed
        assertNull(SecurityContextHolder.getContext().getAuthentication(), "Authentication should be null");
        verify(filterChain, times(1)).doFilter(request, response);
    }
}