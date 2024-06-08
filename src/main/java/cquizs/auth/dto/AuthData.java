package cquizs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 인증 관련 데이터 전송 객체 클래스.
 * 각 요청 및 응답 데이터를 담는 내부 클래스로 구성
 */
public class AuthData {

    /**
     * JWT 토큰을 담는 클래스.
     */
    @Data
    @AllArgsConstructor
    public static class JwtToken{
        private String accessToken; // 액세스 토큰
        private String refreshToken; // 리프레시 토큰
    }

    /**
     * 회원 가입 요청 데이터를 담는 클래스
     */
    @Data
    public static class Join {
        private String username;
        private String password;
        private String nickname;
    }

    /**
     * 로그인 요청 데이터를 담는 클래스
     */
    @Data
    public static class Login {
        private String username;
        private String password;
    }
}
