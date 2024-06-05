package cquizs.auth.repository;

import cquizs.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

    // 커스텀 JPA 구문
    boolean existsByUsername(String username);

    User findByUsername(String username);
}
