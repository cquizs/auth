package cquizs.auth.service;

import cquizs.auth.dto.AuthData.Join;
import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.dto.AuthData.Login;

public interface AuthService {
    void join(Join join);

    JwtToken login(Login login);
}
