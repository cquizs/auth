package cquizs.auth.entity;

import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;


/**
 * 사용자 엔티티 클래스.
 * 사용자 정보를 데이터베이스에 저장하기 위한 클래스.
 */
@Entity
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username; // 사용자 ID

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private String nickname = "이름 없음";

    @Column(nullable = false)
    private Boolean emailVerified = true;

    @CreationTimestamp
    private LocalDateTime createdAt;

    @UpdateTimestamp
    private LocalDateTime updatedAt;

    @Column(nullable = false)
    private String role = "ROLE_USER";
}
