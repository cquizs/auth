package cquizs.auth.repository;

import cquizs.auth.entity.BlackList;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * JWT 블랙리스트 리포지토리
 */
public interface BlacklistRepository extends JpaRepository<BlackList, String> {
    Optional<BlackList> findByToken(String token);
}
