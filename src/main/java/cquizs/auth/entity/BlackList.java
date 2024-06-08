package cquizs.auth.entity;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.LocalDateTime;

/**
 * JWT 블랙 리스트 엔티티
 */
@Entity
@Data
public class BlackList {

    @Id
    @Column(length = 512, nullable = false)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiryDate;
}
