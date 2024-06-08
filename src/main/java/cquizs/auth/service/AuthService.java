package cquizs.auth.service;

import cquizs.auth.dto.AuthData.Join;
import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.dto.AuthData.Login;

/**
 * 사용자 인증 및 JWT 토큰 관리를 위한 서비스 계층 역할
 */
public interface AuthService {

    /**
     * 사용자 가입 처리
     *
     * @param join 가입 정보
     */
    void join(Join join);

    /**
     * 사용자의 로그인 요청을 처리하고 JWT 토큰을 발급
     *
     * @param login 로그인 정보
     * @return 발급된 JWT 토큰
     */
    JwtToken login(Login login);

    /**
     * Refresh 토큰을 사용하여 새로운 JWT 토큰을 발급
     *
     * @param refreshToken Refresh 토큰
     * @return 새로 발급한 JWT 토큰
     */
    JwtToken refresh(String refreshToken);

    void logout(String refreshToken);
}
