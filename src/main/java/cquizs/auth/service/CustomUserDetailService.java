package cquizs.auth.service;

import cquizs.auth.entity.User;
import cquizs.auth.entity.UserPrincipal;
import cquizs.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * User 인증에 필요한 User 정보 로드
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * User 이름으로 User 정보 로드
     *
     * @param username User 이름(Id)
     * @return UserDetails 상속 받은 UserPrincipal
     * @throws UsernameNotFoundException 사용자 이름으로 사용자를 찾을 수 없는 경우
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (Objects.isNull(user)) {
            throw new UsernameNotFoundException("존재하지 않는 사용자 이름");
        }
        return new UserPrincipal(user);
    }
}
