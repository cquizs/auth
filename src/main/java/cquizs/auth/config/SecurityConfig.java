package cquizs.auth.config;

import cquizs.auth.jwt.JWTFilter;
import cquizs.auth.jwt.JWTUtil;
import cquizs.auth.jwt.LoginFilter;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

@Configuration // Spring Security 설정 클래스임을 나타내는 어노테이션
@EnableWebSecurity // Spring Security 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
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
        // CORS 설정
        //        http.cors(cors -> cors
        //                .configurationSource(new CorsConfigurationSource() {
        //                    @Override
        //                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        //                        CorsConfiguration configuration = new CorsConfiguration();
        //                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
        //                        configuration.setAllowedMethods(Collections.singletonList("*"));
        //                        configuration.setAllowCredentials(true);
        //                        configuration.setAllowedHeaders(Collections.singletonList("*"));
        //                        configuration.setMaxAge(3600L);
        // configuration.setExposedHeaders(Collections.singletonList("Authorization"));
        // return configuration;
        // }
        // })
        // );

        http
                .csrf().disable() // csrf disable
                .formLogin().disable() // Form 로그인 방식 disable
                .httpBasic().disable(); // httpBasic 인증 방식 disable

        // 경로별 인가 작업
        http
                .authorizeHttpRequests(auth -> auth
                        .antMatchers("/", "/login", "/join").permitAll()
                        .antMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                );

        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        // 필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 등록 필요
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // 세션 설정
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        return http.build();
    }
}
