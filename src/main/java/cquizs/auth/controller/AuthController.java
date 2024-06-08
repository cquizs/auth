package cquizs.auth.controller;

import cquizs.auth.dto.AuthData.Join;
import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.dto.AuthData.Login;
import cquizs.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Objects;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/join")
    public ResponseEntity<Void> join(@RequestBody Join join) {
        authService.join(join);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody Login login, HttpServletResponse response) {
        log.debug("로그인 : {} ",login);
        JwtToken token = authService.login(login);
        if (Objects.isNull(token)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        response.addCookie(createCookie(token.getRefreshToken()));
        return ResponseEntity.ok(token);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtToken> refresh(HttpServletRequest request, HttpServletResponse response) {
        Cookie refreshCookie = getRefreshCookie(request);
        if(Objects.isNull(refreshCookie)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        JwtToken token = authService.refresh(refreshCookie.getValue());
        response.addCookie(createCookie(token.getRefreshToken()));
        log.debug("refresh 완료");
        return ResponseEntity.ok(token);
    }

    private Cookie getRefreshCookie(HttpServletRequest request) {
        return Arrays.stream(request.getCookies())
                .filter(cookie -> "refreshToken".equals(cookie.getName()))
                .findFirst()
                .orElse(null);
    }

    private static Cookie createCookie(String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
//        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(3600000);
        return cookie;
    }
}
