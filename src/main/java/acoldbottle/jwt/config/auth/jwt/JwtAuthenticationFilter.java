package acoldbottle.jwt.config.auth.jwt;

import acoldbottle.jwt.config.auth.PrincipalDetails;
import acoldbottle.jwt.domain.User;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
 * /login 요청해서 username, password 전송하면 (post)
 * UsernamePasswordAuthenticationFilter 동작을 함
 */

@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;


    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter : 로그인 시도 중");
        /**
         * 1. username, password 를 받아서
         * 2. 정상인지 로그인 시도를 함. AuthenticationManager 로 로그인 시도를 하면
         *    PrincipalDetailsService 가 호출. -> loadUserByUsername 함수가 실행됨
         * 3. PrincipalDetails 를 세션에 담고 (권한관리를 위헤)
         * 4. JWT 토큰을 만들어서 응답해주면 됨
         */
        try {

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("user={}", user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
            // PrincipalDetailsService 의 loadByUsername 함수가 실행됨
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            // authentication 객체가 session 영역에 저장됨 --> 로그인이 되었다는 뜻
            // DB에 있는 username, password 가 일치한다
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("principalDetails.getUser().getUsername()={}", principalDetails.getUser().getUsername());
            // authentication 객체가 session 영역에 저장을 해야하고 그 방법이 return 해주면 됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한처리때문에 session을 넣어줌
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *  attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
     *  JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("successfulAuthentication 실행됨 => 인증 완료되었다는 뜻");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = com.auth0.jwt.JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 100)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
