package example.springsecurityjwt;

import example.springsecurityjwt.config.RsaKeyConfigProperties;
import example.springsecurityjwt.entity.Role;
import example.springsecurityjwt.entity.User;
import example.springsecurityjwt.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableConfigurationProperties(RsaKeyConfigProperties.class)
@SpringBootApplication
public class SpringSecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtApplication.class, args);
    }

    @Bean
    public CommandLineRunner initializeUser(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        return args -> {
            User user = new User();
            user.setUsername("user");
            user.setEmail("example@gmail.com");
            user.setRole(Role.USER);
            user.setPassword(passwordEncoder.encode("password"));
            userRepository.save(user);

            User user2 = new User();
            user2.setUsername("user2");
            user2.setEmail("example@gmail2.com");
            user2.setRole(Role.ADMIN);
            user2.setPassword(passwordEncoder.encode("password"));
            userRepository.save(user2);
        };
    }

}
