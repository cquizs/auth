package cquizs.auth.entity;

import cquizs.auth.dto.JoinDto;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Setter
@Getter
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String username;

    private String password;

    private String role;

    public static User of(JoinDto joinDto) {
        User user = new User();
        user.setUsername(joinDto.getUsername());
        user.setPassword(joinDto.getPassword());
        user.setRole("ROLE_USER");

        return user;
    }
}
