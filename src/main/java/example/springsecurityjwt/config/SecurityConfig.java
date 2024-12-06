package example.springsecurityjwt.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import example.springsecurityjwt.auth.JpaUserDetailsService;
import example.springsecurityjwt.entity.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Security configuration class for the Spring Boot application.
 * <p>
 * This configuration enables OAuth2-based resource server functionality with JWT (JSON Web Tokens)
 * for authentication and authorization. It integrates roles and scopes from the token claims
 * to provide granular control over access.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    private RsaKeyConfigProperties rsaKeyConfigProperties;
    private JpaUserDetailsService userDetailsService;

    @Autowired
    public void setRsaKeyConfigProperties(RsaKeyConfigProperties rsaKeyConfigProperties, JpaUserDetailsService userDetailsService) {
        this.rsaKeyConfigProperties = rsaKeyConfigProperties;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(authProvider);
    }

    /**
     * Configures the Spring Security filter chain.
     *
     * <p>Features enabled:
     * <ul>
     *   <li>Disables CSRF (not needed for APIs).</li>
     *   <li>Configures stateless session management.</li>
     *   <li>Defines endpoint-level authorization rules based on roles.</li>
     *   <li>Configures JWT decoding and authentication.</li>
     * </ul>
     *
     * @param http the HttpSecurity object to configure.
     * @return the configured SecurityFilterChain.
     * @throws Exception in case of misconfiguration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/user").hasRole(Role.USER.name());
                    auth.requestMatchers(HttpMethod.GET, "/admin").hasRole(Role.ADMIN.name());
                    auth.requestMatchers("/all").permitAll();
                    auth.requestMatchers("/error/**").permitAll();
                    auth.requestMatchers("/auth/**").permitAll();
                    auth.anyRequest().authenticated();
                })
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer((oauth2) -> oauth2.jwt((jwt)-> jwt
                                        .decoder(jwtDecoder())
                                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        ))
                .userDetailsService(userDetailsService)
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    /**
     * Converts JWT claims into Spring Security authorities based on roles and scopes.
     *
     * @return un JwtAuthenticationConverter configurado.
     */
    private Converter<Jwt,? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>();

            List<String> roles = jwt.getClaimAsStringList("role");
            if (roles != null) {
                for (String role : roles) {
                    authorities.add(new SimpleGrantedAuthority(role));
                }
            }

            List<String> scopes = jwt.getClaimAsStringList("scope");
            if (scopes != null) {
                for (String scope : scopes) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
                }
            }

            return authorities;
        });

        return converter;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeyConfigProperties.publicKey()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeyConfigProperties.publicKey()).privateKey(rsaKeyConfigProperties.privateKey()).build();

        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
