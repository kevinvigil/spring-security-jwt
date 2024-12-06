package example.springsecurityjwt.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

/**
 * A service responsible for generating JWT tokens for authenticated users.
 *
 * <ul>
 *     <li>Uses a `JwtEncoder` to create signed JWT tokens.</li>
 *     <li>Includes claims such as issuer, issued date, expiration, subject, and user roles.</li>
 * </ul>
 */
@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final JwtEncoder jwtEncoder;

    @Autowired
    public AuthService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * Generates a JWT token for a given authenticated user.
     *
     * @param authentication the authenticated user details.
     * @return a signed JWT token string.
     */
    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();

        String role = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(12, ChronoUnit.HOURS))
                .subject(authentication.getName())
                .claim("role", role)
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
