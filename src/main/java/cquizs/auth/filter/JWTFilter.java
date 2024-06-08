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
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    public final String AUTHORIZATION_HEADER = "Authorization";
    public final String PREFIX = "Bearer ";
    private final JWTUtil jwtUtil;
    private final CustomUserDetailService customUserDetailService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // 인증이 안된 경우, 토큰이 존재하지 않은 경우 -> UsernamePasswordAuthenticationFilter로 넘어간다.
        String accessToken = extractToken(request);

        // accessToken이 존재하는 경우 token 추출
        if(Objects.nonNull(accessToken) && jwtUtil.validateToken(accessToken)){
            String username = jwtUtil.getUsername(accessToken);
            if (Objects.nonNull(username) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
                UserDetails userDetails = customUserDetailService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        } else{
          log.debug("토큰이 존재하지 않음");
        }
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String authorization = request.getHeader(AUTHORIZATION_HEADER);
        if(authorization != null && authorization.startsWith(PREFIX)) {
            return authorization.substring(PREFIX.length());
        }
        return null;
    }
}
