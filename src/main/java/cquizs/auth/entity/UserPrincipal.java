package cquizs.auth.entity;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Spring Security의 UserDetails 인터페이스를 구현하여 사용자 인증 정보 제공
 */
@Data
@RequiredArgsConstructor
public class UserPrincipal implements UserDetails {

    private final User user;

    /**
     * User 권한(역할)을 반환
     *
     * @return 사용자의 역할을 담은 GrantedAuthority 컬렉션
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> list = new ArrayList<>();
        list.add(() -> user.getRole());
        return list;
    }

    /**
     * User 비밀번호를 반환
     *
     * @return User 비밀번호
     */
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    /**
     * User 이름(아이디)를 반환
     *
     * @return User 이름
     */
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /**
     * 계정 만료되었는지 여부
     *
     * @return 만료되지 않았을 시 true, 만료시 false
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 계정 잠금 여부
     *
     * @return 잠기지않았다면 true, 잠김시 false
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 자격 만료 여부
     *
     * @return 만료 되지 않았을시 true, 만료시 false
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 활성화되었는지 여부
     *
     * @return 활성화시 true, 아니면 false
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
