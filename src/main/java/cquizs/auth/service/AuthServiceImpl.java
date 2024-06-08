package cquizs.auth.service;

import cquizs.auth.dto.AuthData;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    @Override
    public void join(Join join) {
        if (userRepository.existsByUsername(join.getUsername())) {
            log.debug("이미 존재하는 회원입니다.");
            return;
        }

        String encodedPassword = bCryptPasswordEncoder.encode(join.getPassword());

        User user = new User();
        user.setUsername(join.getUsername());
        user.setPassword(encodedPassword);
        user.setNickname("임시 이름");
        user.setRole("ROLE_USER");

        userRepository.save(user);
    }

    @Override
    public JwtToken login(Login login) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()
                    ));
            UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();

            log.debug("로그인 : {}", principal.getUser());
            return jwtUtil.createToken(principal.getUser());
        } catch (AuthenticationException e) {
            log.error("로그인 실패");
            return null;
        }
    }

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
