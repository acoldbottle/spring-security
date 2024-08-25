package acoldbottle.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        /**
         * 토큰: ex) cos 이걸 만들어줘야함. id,pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
         * 요청할 때 마다 header에 Authorization에 value 값으로 토큰을 가지고 온다
         * 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰인지 검증만 하면 된다. --> (RSA, HS256)
         */
        if (req.getMethod().equals("POST")) {
            log.info("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            log.info("header={}", headerAuth);
            log.info("필터3");

            if (headerAuth.equals("cos")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("no access");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
