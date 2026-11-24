package tn.epi.portal;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/error", "/actuator/health/**", "/actuator/prometheus").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())          // refus par defaut
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults())
            .headers(h -> h.contentSecurityPolicy(csp ->
                csp.policyDirectives("default-src 'self'; frame-ancestors 'none'")));
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();   // bcrypt
    }

    /**
     * Comptes de demonstration. Les mots de passe viennent de l'environnement
     * (APP_USER_PASSWORD, APP_ADMIN_PASSWORD), jamais du code.
     * Un compte qui a trop d'echecs recents est renvoye comme verrouille.
     */
    @Bean
    UserDetailsService users(PasswordEncoder encoder, LoginAttemptService attempts,
                             @Value("${app.user.password}") String userPassword,
                             @Value("${app.admin.password}") String adminPassword) {
        InMemoryUserDetailsManager delegate = new InMemoryUserDetailsManager(
            User.withUsername("alice").password(encoder.encode(userPassword)).roles("USER").build(),
            User.withUsername("admin").password(encoder.encode(adminPassword)).roles("USER", "ADMIN").build());
        return username -> {
            UserDetails user = delegate.loadUserByUsername(username);
            return attempts.isBlocked(username)
                ? User.withUserDetails(user).accountLocked(true).build()
                : user;
        };
    }
}
