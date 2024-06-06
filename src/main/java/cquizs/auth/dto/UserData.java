package cquizs.auth.dto;

import lombok.Data;

public class UserData {

    @Data
    public static class Join {
        private String username;
        private String password;

    }
}
