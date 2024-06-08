package cquizs.auth.config;

import cquizs.auth.AuthApplication;
import cquizs.auth.filter.JWTFilter;
import cquizs.auth.service.CustomUserDetailService;
import cquizs.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Spring Security 설정 클래스
 */
@Configuration // Spring Security 설정 클래스임을 나타내는 어노테이션
@EnableWebSecurity // Spring Security 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailService customUserDetailService;
    private final JWTUtil jwtUtil;

    /**
     * AuthenticationManager 빈 등록
     *
     * @param configuration AuthenticationConfiguration Class
     * @return AuthenticationManager Class
     * @throws Exception 예외 발생시
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * BCryptPasswordEncoder 빈 등록
     *
     * @return BCryptPasswordEncoder Class
     */
    @Bean
    public BCryptPasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * SecurityFilterChain 설정 구성
     *
     * @param http HttpSecurity Class
     * @return SecurityFilterChain Class
     * @throws Exception 예외 발생 시
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthApplication authApplication) throws Exception {
        http
                .csrf().disable() // CSRF 보호 비활성화
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 상태 비저장 모드로 설정
                .and()
                .authorizeHttpRequests(auth -> auth
                        .antMatchers("/", "/auth/join", "/auth/login").permitAll() // 루트 경로, 로그인 및 가입 경로는 모든 사용자에게 허용
                        .antMatchers("/admin").hasRole("ADMIN") // /admin 경로는 ADMIN 역할만 허용
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증된 사용자만 허용
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/auth/logout") // 로그아웃 성공 후 리다이렉트 경로
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.setStatus(HttpStatus.OK.value()); // 로그아웃 성공 시 상태 코드 설정
                            }
                        })
                )
                // JWT 필터를 UsernamePasswordAuthenticationFilter 전에 추가
                .addFilterBefore(new JWTFilter(jwtUtil, customUserDetailService), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
