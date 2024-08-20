package com.sparta.springauth.filter;

import com.sparta.springauth.entity.User;
import com.sparta.springauth.jwt.JwtUtil;
import com.sparta.springauth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

@Slf4j(topic = "AuthFilter")
@Component
@RequiredArgsConstructor
@Order(2)
public class AuthFilter implements Filter {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 전처리
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String url = httpServletRequest.getRequestURI();

        log.info("AuthFilter 실행");
        if (StringUtils.hasText(url) && (url.startsWith("/api/user") || url.startsWith("/css") || url.startsWith("/js"))) {
            // 인증이 필요없으면 다음 filter 로 이동
            log.info("인증 처리를 하지 않는 URL : " + url);
            chain.doFilter(request, response);
        } else {
            // 인증 처리
            // 토큰 확인
            String tokenValue = jwtUtil.getTokenFromRequest(httpServletRequest);

            if (StringUtils.hasText(tokenValue)) { // 토큰이 존재하면
                String token = jwtUtil.substringToken(tokenValue);

                // 토큰 검증
                if (!jwtUtil.validateToken(token)) {
                    throw new IllegalArgumentException("Token Error");
                }

                // 토큰에서 사용자 정보 가져오기
                Claims info = jwtUtil.getUserInfoFromToken(token);

                User user = userRepository.findByUsername(info.getSubject()).orElseThrow(
                        () -> new NullPointerException("Not Found User")
                );

                request.setAttribute("user", user);
                chain.doFilter(request, response);
            } else {
                throw new IllegalArgumentException("Not Found Token");
            }
        }
    }

}
