package example.springsecurityjwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSAKeyManager
 * <p>
 * This component is responsible for loading and managing RSA keys (`private-key.pem` and `public-key.pem`)
 * required for JWT signing. The application relies on the user to create the necessary RSA keys
 * and place them in the appropriate directory before the application starts.
 *
 * <p>Key expectations:
 * <ol>
 *   <li>The user must create a `certs` directory within the `resources` folder.</li>
 *   <li>The user must generate a private key (`private-key.pem`) and a public key (`public-key.pem`)
 *       using OpenSSL or similar tools.</li>
 *   <li>The private key must be converted to PKCS#8 format for compatibility with JWT.</li>
 *   <li>All required files must be placed in the `certs` directory for the application to load them.</li>
 * </ol>
 *
 * <p>This component ensures that the keys are properly loaded into the application for use in
 * Spring Security's JWT-based authentication process.
 *
 * <p>For detailed setup instructions, refer to the `README.md` file in the project repository.
 */
@ConfigurationProperties(prefix = "rsa")
public record RsaKeyConfigProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey ) {}
