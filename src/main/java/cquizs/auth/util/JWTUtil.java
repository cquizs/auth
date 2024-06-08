package cquizs.auth.util;

import cquizs.auth.dto.AuthData.JwtToken;
import cquizs.auth.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

/**
 * JWTUtil 클래스는 JWT 토큰 생성, 유효성 검증 ,클레임 추출 등의 기능 제공
 */
@Slf4j
@Component
public class JWTUtil {

    private final Key key; // JWT 서명에 사용할 키
    private final long accessTokenValidity; // 액세스 토큰 유효 기간
    private final long refreshTokenValidity; // 리프레시 토큰의 유효 기간

    /**
     * JWTUtil 생성자.
     *
     * @param secretKey JWT 서명에 사용할 비밀키
     * @param accessTokenValidity 액세스 토큰의 유효 기간 (밀리초)
     * @param refreshTokenValidity 리프레시 토큰의 유효 기간 (밀리초)
     */
    public JWTUtil(@Value("${jwt.secret}") String secretKey,
                   @Value("${jwt.accessTokenExpiration}") long accessTokenValidity,
                   @Value("${jwt.refreshTokenExpiration}") long refreshTokenValidity) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    /**
     * 사용자 정보를 기반으로 액세스 토큰과 리프레시 토큰 생성.
     *
     * @param user 사용자 정보
     * @return 생성된 JWT 토큰 객체
     */
    public JwtToken createToken(User user) {
        Date now = new Date();
        Date accessTokenExpire = new Date(now.getTime() + accessTokenValidity);
        Date refreshTokenExpire = new Date(now.getTime() + refreshTokenValidity);

        String accessToken = Jwts.builder()
                .claim("username", user.getUsername())
                .claim("role", user.getRole())
                .claim("nickname", user.getNickname())
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiration(accessTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = Jwts.builder()
                .claim("username", user.getUsername())
                .subject(user.getId().toString())
                .issuedAt(now)
                .expiration(refreshTokenExpire)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();


        return new JwtToken(accessToken, refreshToken);
    }

    /**
     * JWT 토큰에서 클레임 추출
     *
     * @param token JWT 토큰
     * @return 추출된 클레임
     */
    public Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * JWT 토큰의 유효성 검사
     *
     * @param token 검사할 JWT 토큰
     * @return 유효한 토큰인지 여부
     */
    public boolean validateToken(String token) {
        try{
            extractClaims(token);
            return true;
        }catch(Exception e){
            return false;
        }
    }

    /**
     * JWT 토큰에서 사용자 ID 추출
     *
     * @param token JWT 토큰
     * @return User ID
     */
    public Long getUserId(String token){
        return Long.parseLong(extractClaims(token).getSubject());
    }

    /**
     * JWT 토큰에서 사용자 이름(아이디) 추출
     *
     * @param token JWT 토큰
     * @return 사용자 이름
     */
    public String getUsername(String token){
        return (String) extractClaims(token).get("username");
    }

    /**
     * JWT 토큰에서 사용자 역할 추출
     *
     * @param token JWT 토큰
     * @return 사용자 역할
     */
    public String getRole(String token) {
        return (String) extractClaims(token).get("role");
    }

    public Date getExpiration(String token) {
        return extractClaims(token).getExpiration();
    }
}
