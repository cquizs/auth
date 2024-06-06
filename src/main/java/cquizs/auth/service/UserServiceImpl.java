package cquizs.auth.service;

import cquizs.auth.dto.UserData;
import cquizs.auth.dto.UserData.Join;
import cquizs.auth.entity.User;
import cquizs.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    // 생성자 주입
    private final UserRepository userRepository;

    @Override
    public void join(Join join) {
        String username = join.getUsername();
        String password = join.getPassword();

        // 존재한다면 return
        if(userRepository.existsByUsername(username)){
            return;
        }

        // 비밀번호 단방향 해싱
        password = bCryptPasswordEncoder.encode(password);
        User joinUser = User.create(username, password);

        // 데이터베이스 저장
        userRepository.save(joinUser);
    }
}
