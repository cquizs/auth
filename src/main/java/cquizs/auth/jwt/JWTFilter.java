package cquizs.auth.jwt;

import cquizs.auth.dto.CustomUserDetails;
import cquizs.auth.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");

        if(Objects.isNull(authorization) || !authorization.startsWith("Bearer ")) {
            log.debug("로그인 인증 실패 [ token null ]");
            filterChain.doFilter(request, response);

            return;
        }

        String token = authorization.split(" ")[1];
        if(jwtUtil.isExpired(token)){
            log.debug("토큰 만료");
            filterChain.doFilter(request, response);

            return;
        }

        String userName = jwtUtil.getUserName(token);
        String role = jwtUtil.getRole(token);

        User user = new User();
        user.setUsername(userName);
        user.setPassword("tempPassword");
        user.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);
    }
}
