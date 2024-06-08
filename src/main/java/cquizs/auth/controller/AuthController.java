package cquizs.auth.controller;

import cquizs.auth.dto.AuthData.Join;
import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.dto.AuthData.Login;
import cquizs.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.RequestContextFilter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Objects;

/**
 * 인증 관련 요청을 처리하는 컨트롤러
 */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Value("${jwt.refreshTokenExpiration}")
    private int REFRESH_TOKEN_EXPIRY;
    private String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

    /**
     * 회원 가입 요청 처리
     *
     * @param join 가입 정보
     * @return HTTP 상태 코드 200
     */
    @PostMapping("/join")
    public ResponseEntity<Void> join(@RequestBody Join join) {
        log.debug("회원 가입 : {} ", join);
        authService.join(join);
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * 로그인 요청을 처리하고 JWT 토큰을 발급
     *
     * @param login    로그인 정보
     * @param response HTTP 응답
     * @return 발급된 JWT 토큰
     */
    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody Login login, HttpServletResponse response) {
        log.debug("로그인 요청 : {} ", login);
        JwtToken token = authService.login(login);
        if (Objects.isNull(token)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        response.addCookie(createCookie(token.getRefreshToken()));
        return ResponseEntity.ok(token);
    }

    /**
     * Refresh 토큰을 사용하여 Access 토큰 재발급
     *
     * @param request  HTTP 요청
     * @param response HTTP 응답
     * @return 재발급된 JWT 토큰
     */
    @PostMapping("/refresh")
    public ResponseEntity<JwtToken> refresh(HttpServletRequest request, HttpServletResponse response) {
        log.debug("{}", request);
        Cookie refreshCookie = getRefreshCookie(request);
        if (Objects.isNull(refreshCookie)) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        JwtToken token = authService.refresh(refreshCookie.getValue());
        response.addCookie(createCookie(token.getRefreshToken()));
        log.debug("JWT Token 재발급");
        return ResponseEntity.ok(token);
    }

    /**
     * 로그아웃 요청 처리 후 Refresh 토큰 쿠키 삭제
     *
     * @param response HTTP 응답
     * @return HTTP 상태 코드 200 OK
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie refreshCookie = getRefreshCookie(request);
        if (Objects.nonNull(refreshCookie)) {
            authService.logout(refreshCookie.getValue());
            Cookie cookie = createCookie(null);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
        }
        log.debug("로그아웃 성공");
        return new ResponseEntity<>(HttpStatus.OK);
    }

    /**
     * HTTP 요청에서 Refresh 토큰 쿠키를 추출
     *
     * @param request HTTP 요청
     * @return Refresh 토큰 쿠키
     */
    private Cookie getRefreshCookie(HttpServletRequest request) {
        return Arrays.stream(request.getCookies())
                .filter(cookie -> REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName()))
                .findFirst()
                .orElse(null);
    }

    /**
     * Refresh 토큰 쿠키 생성
     *
     * @param refreshToken Refresh 토큰 값
     * @return 생성된 쿠키
     */
    private Cookie createCookie(String refreshToken) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        cookie.setHttpOnly(true);
//        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(REFRESH_TOKEN_EXPIRY);
        return cookie;
    }
}
