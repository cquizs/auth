package cquizs.auth.repository;

import cquizs.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * 사용자 엔티티를 관리하는 JPA 저장소
 */
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * 주어진 username을 가진 user가 존재하는지 확인
     *
     * @param username 사용자 이름
     * @return 존재하면 true, 그렇지 않으면 false
     */
    boolean existsByUsername(String username);

    /**
     * 주어진 사용자 이름으로 사용자를 찾습니다.
     *
     * @param username 사용자 이름
     * @return 사용자 엔티티
     */
    User findByUsername(String username);
}
