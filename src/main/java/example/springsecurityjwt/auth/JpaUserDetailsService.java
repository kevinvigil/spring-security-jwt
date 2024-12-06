package example.springsecurityjwt.auth;

import example.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * A custom implementation of Spring Security's `UserDetailsService` that integrates with a JPA repository.
 *
 * <ul>
 *     <li>Loads user details from the database using the `UserRepository`.</li>
 *     <li>Converts the database user entity into a Spring Security `UserDetails` object.</li>
 * </ul>
 */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public JpaUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Loads a user by username from the database.
     *
     * @param username the username of the user to load.
     * @return a `UserDetails` object representing the authenticated user.
     * @throws UsernameNotFoundException if the username is not found in the database.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = userRepository
                .findByUsername(username)
                .map(AuthUser::new)
                .orElseThrow(() -> new UsernameNotFoundException("User name not found: " + username));

        // Create a Spring Security UserDetails object with the user's data.
        return org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getAuthority())
                .roles(user.getAuthority())
                .build();
    }
}
