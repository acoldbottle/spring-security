package acoldbottle.jwt.config;


import acoldbottle.jwt.config.auth.jwt.JwtAuthenticationFilter;
import acoldbottle.jwt.config.auth.jwt.JwtAuthorizationFilter;
import acoldbottle.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);

        AuthenticationManager authenticationManager = sharedObject.build();

        http.authenticationManager(authenticationManager);

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilter(corsConfig.corsFilter())
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilter(new JwtAuthenticationFilter(authenticationManager))
                .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/v1/user/**").authenticated()
                        .requestMatchers("/api/v1/manager/**").hasAnyAuthority("MANAGER", "ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasAuthority("ADMIN")
                        .anyRequest().permitAll())
                .build();

    }

}
