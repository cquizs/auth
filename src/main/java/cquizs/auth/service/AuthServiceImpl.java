package cquizs.auth.service;

import cquizs.auth.dto.AuthData.Join;
import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.dto.AuthData.Login;
import cquizs.auth.entity.User;
import cquizs.auth.entity.UserPrincipal;
import cquizs.auth.repository.UserRepository;
import cquizs.auth.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 사용자 인증 및 JWT 토큰 관리
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    /**
     * 회원 가입 처리
     * @param join 가입 정보
     */
    @Override
    public void join(Join join) {
        if (userRepository.existsByUsername(join.getUsername())) {
            log.debug("이미 존재하는 회원입니다.");
            return;
        }

        // 비밀번호 암호화
        String encodedPassword = bCryptPasswordEncoder.encode(join.getPassword());

        // 사용자 정보 설정
        User user = new User();
        user.setUsername(join.getUsername());
        user.setPassword(encodedPassword);
        if (join.getNickname() != null) {
            user.setNickname(join.getNickname());
        }

        // 사용자 정보 저장
        userRepository.save(user);
    }

    /**
     * 사용자의 로그인 요청을 처리하고 JWT 토큰을 발급
     *
     * @param login 로그인 정보
     * @return 발급된 JWT 토큰
     */
    @Override
    public JwtToken login(Login login) {
        log.debug("login : {}", login);
        try {
            // 사용자 인증
            Authentication authentication = authenticationManager
                    .authenticate( new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()
                    ));
            UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();

            return jwtUtil.createToken(principal.getUser());
        } catch (AuthenticationException e) {
            log.error("로그인 실패");
            return null;
        }
    }

    /**
     * Refresh 토큰을 사용하여 새로운 JWT 토큰 발급
     *
     * @param refreshToken Refresh 토큰
     * @return 새로 발급된 JWT 토큰
     */
    @Override
    public JwtToken refresh(String refreshToken) {
        if (jwtUtil.validateToken(refreshToken)) {
            String username = jwtUtil.getUsername(refreshToken);
            log.debug("username : {} ", username);
            User user = userRepository.findByUsername(username);
            return jwtUtil.createToken(user);
        }
        return null;
    }
}
