package cquizs.auth.service;

import cquizs.auth.dto.UserData;
import cquizs.auth.dto.UserData.Join;

public interface UserService {
    public void join(Join join);
}
