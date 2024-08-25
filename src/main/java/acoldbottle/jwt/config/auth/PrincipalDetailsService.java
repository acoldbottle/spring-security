package acoldbottle.jwt.config.auth;

import acoldbottle.jwt.domain.User;
import acoldbottle.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * http://localhost:8080/login
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("PrincipalDetailsService --> loadUserByUsername()");
        User userEntity = userRepository.findByUsername(username);
        return new PrincipalDetails(userEntity);
    }
}
