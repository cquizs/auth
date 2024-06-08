package cquizs.auth.controller;

import cquizs.auth.dto.AuthData;
import cquizs.auth.dto.AuthData.Join;
import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Objects;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/join")
    public ResponseEntity<Void> register(@RequestBody Join join) {
        authService.join(join);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody AuthData.Login login, HttpServletResponse response) {
        JwtToken token = authService.login(login);
        if (Objects.isNull(token)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        response.addCookie(createCookie(token));
        return ResponseEntity.ok(token);
    }

    private static Cookie createCookie(JwtToken token) {
        Cookie cookie = new Cookie("access_token", token.getAccessToken());
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(60 * 60 * 24);
        return cookie;
    }
}
