package cquizs.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration // Spring Security 설정 클래스임을 나타내는 어노테이션
@EnableWebSecurity // Spring Security를 활성화
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .csrf(auth -> auth.disable()); // CSRF 보호를 비활성화 default : Enable

        // 5.7 이후부터는 requestMatchers 가끔 오류가 발생하면 antMatchers을 사용하면 됨
        // http
        // .authorizeHttpRequests(auth -> auth
        // .requestMatchers("/","/login).permitAll()
        // .requestMatchers("/admin").hasRole("ADMIN")
        // .requestMatchers("/mypage/**").hasAnyRole("ADMIN", "USER")
        // .anyRequest().authenticated()
        // );

        http
                .authorizeHttpRequests(auth -> auth // HTTP 요청에 대한 권한 설정
                        .antMatchers("/", "/login","/join").permitAll() // 루트 경로와 /login 경로 /join 경로는 모든 사용자에게 접근을 허용
                        .antMatchers("/admin").hasRole("ADMIN") // /admin 경로는 ADMIN 역할을 가진 사용자만 접근할 수 있음
                        .antMatchers("/myPage/**").hasAnyRole("ADMIN", "USER") // /mypage /로 시작하는 모든 경로는 ADMIN 또는 USER 역할을 가진 사용자만 접근 할 수 있음
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증된 사용자만 접근할 수 있음
                );

//        폼 로그인 방식
//        http
//                .formLogin(auth -> auth // 로그인 설정
//                        .loginPage("/login") // 사용자 정의 로그인 페이지 설정
//                        .loginProcessingUrl("/login") // 사용자 정의 로그인 폼의 액션 URL 설정
//                        .permitAll() // 로그인 페이지는 모든 사용자에게 접근 허용
//                );

        // HTTP BASE64 방식
        http
                .httpBasic(Customizer.withDefaults());



        http
                .sessionManagement(auth -> auth
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(true)

                );

        http
                .sessionManagement(auth -> auth
                        .sessionFixation().changeSessionId()
                );

        return http.build(); // 설정된 보안 필터 체인 반환
    }
}
