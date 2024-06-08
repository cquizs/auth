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

@Slf4j
@Component
public class JWTUtil {

    private final Key key;

    private final long accessTokenValidity;
    private final long refreshTokenValidity;

    public JWTUtil(@Value("${jwt.secret}") String secretKey,
                   @Value("${jwt.accessTokenExpiration}") long accessTokenValidity,
                   @Value("${jwt.refreshTokenExpiration}") long refreshTokenValidity) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

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

    // 토큰에서 클레임 추출
    public Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try{
            extractClaims(token);
            return true;
        }catch(Exception e){
            return false;
        }
    }

    public Long getUserId(String token){
        return Long.parseLong(extractClaims(token).getSubject());
    }

    public String getUsername(String token){
        return (String) extractClaims(token).get("username");
    }

    public String getRole(String token) {
        return (String) extractClaims(token).get("role");
    }
}
