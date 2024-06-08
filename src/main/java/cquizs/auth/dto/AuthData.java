package cquizs.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

public class AuthData {

    @Data
    @AllArgsConstructor
    public static class JwtToken{
        private String accessToken;
        private String refreshToken;
    }


    @Data
    public static class Join {
        private String username;
        private String password;
    }

    @Data
    public static class Login {
        private String username;
        private String password;
    }
}
