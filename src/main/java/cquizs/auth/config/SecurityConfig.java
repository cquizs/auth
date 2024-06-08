package cquizs.auth.config;

import cquizs.auth.filter.JWTFilter;
import cquizs.auth.service.CustomUserDetailService;
import cquizs.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // Spring Security 설정 클래스임을 나타내는 어노테이션
@EnableWebSecurity // Spring Security 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailService customUserDetailService;
    private final JWTUtil jwtUtil;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // CSRF 보호 비활성화
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 세션을 상태 비저장 모드로 설정

        // 경로별 인가 작업
        http
                .authorizeHttpRequests(auth -> auth
//                        .antMatchers("/", "/login", "/join").permitAll() // 루트 경로, 로그인 및 가입 경로는 모든 사용자에게 허용
                        .antMatchers("/", "/auth/login", "/auth/join").permitAll() // 루트 경로, 로그인 및 가입 경로는 모든 사용자에게 허용
                        .antMatchers("/admin").hasRole("ADMIN") // /admin 경로는 ADMIN 역할만 허용
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증된 사용자만 허용
                );

        http.addFilterBefore(new JWTFilter(jwtUtil, customUserDetailService), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
