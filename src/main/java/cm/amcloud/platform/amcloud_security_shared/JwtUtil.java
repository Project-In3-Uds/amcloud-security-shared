package cm.amcloud.platform.amcloud_security_shared;

import java.security.PublicKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

@Component
public class JwtUtil {

    private PublicKey publicKey;

    // Constructor that accepts PublicKey (as required by SecurityConfig)
    public JwtUtil(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    // No longer using @Value and @PostConstruct here, as PublicKey is injected

    public Claims extractAllClaims(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    public boolean isTokenValid(String token) {
        try {
            return !extractAllClaims(token).getExpiration().before(new java.util.Date());
        } catch (Exception e) {
            return false;
        }
    }

    // You might add other utility methods here, such as:
    // - extractExpiration(String token)
    // - extractRoles(String token)
    // - generateToken(UserDetails userDetails) - if this library also handles token creation
}