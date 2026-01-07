package com.temp.backend.global.jwt;

import com.temp.backend.global.code.ErrorCode;
import com.temp.backend.global.exception.JwtKeyLoadException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${jwt.private-key-path}")
    private String privateKeyPath;

    @Value("${jwt.expiration}")
    private long expirationTime;

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    private PrivateKey getPrivateKey() {
        try {
            String keyContent = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
            
            String privateKeyPEM = keyContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (IOException e) {
            throw new JwtKeyLoadException(ErrorCode.JWT_KEY_LOAD_FAILED, e);
        } catch (Exception e) {
            throw new JwtKeyLoadException(ErrorCode.JWT_KEY_LOAD_FAILED, e);
        }
    }
}
