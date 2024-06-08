package cquizs.auth.filter;

import cquizs.auth.service.CustomUserDetailService;
import cquizs.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * JWTFilter 클래스는 각 요청에 대해 JWT 토큰을 확인한다
 * 유효한 토큰이 있을 시 사용자 인증
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    public final String AUTHORIZATION_HEADER = "Authorization"; // Authorization 헤더 이름
    public final String PREFIX = "Bearer "; // JWT 토큰 접두사

    private final JWTUtil jwtUtil; // JWT 유틸리티 클래스
    private final CustomUserDetailService customUserDetailService; // 사용자 상세 서비스

    /**
     * 각 요청에 대해 필터를 적용
     *
     * @param request     HTTP 요청
     * @param response    HTTP 응답
     * @param filterChain 필터 체인
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // 인증이 안된 경우, 토큰이 존재하지 않은 경우 -> Controller 넘어간다.
        String accessToken = extractToken(request);
        log.debug("없는 토큰 : {} ", accessToken);

        // accessToken 존재하고 유효한 경우
        if (Objects.nonNull(accessToken) && jwtUtil.validateToken(accessToken)) {
            String username = jwtUtil.getUsername(accessToken);
            if (Objects.nonNull(username) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
                UserDetails userDetails = customUserDetailService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        } else {
            log.debug("토큰이 만료되었습니다.");
        }

        filterChain.doFilter(request, response);
    }

    /**
     * HTTP 요청에서 JWT 토큰을 추출
     *
     * @param request HTTP 요청
     * @return 추출된 JWT 토큰
     */
    private String extractToken(HttpServletRequest request) {
        String authorization = request.getHeader(AUTHORIZATION_HEADER);
        if (authorization != null && authorization.startsWith(PREFIX)) {
            return authorization.substring(PREFIX.length());
        }
        return null;
    }
}
