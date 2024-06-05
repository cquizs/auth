package cquizs.auth.service;

import cquizs.auth.dto.JoinDto;
import cquizs.auth.entity.User;
import cquizs.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void join(JoinDto joinDto){
        if(userRepository.existsByUsername(joinDto.getUsername())){
            return;
        }

        joinDto.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
        User data = User.of(joinDto);

        userRepository.save(data);
    }
}
