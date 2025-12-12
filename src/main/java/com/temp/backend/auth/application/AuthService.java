package com.temp.backend.auth.application;

import com.temp.backend.auth.dto.AuthenticationRequest;
import com.temp.backend.auth.dto.RegisterRequest;
import com.temp.backend.domain.user.entity.User;
import com.temp.backend.domain.user.repository.UserRepository;
import com.temp.backend.global.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public String register(RegisterRequest request) {
        User user = User.create(
                request.getFirstname(),
                request.getLastname(),
                request.getEmail(),
                request.getPassword(),
                passwordEncoder,
                request.getRole()
        );
        userRepository.save(user);
        return jwtUtil.generateToken(user.getUsername());
    }

    public String authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("이메일 또는 비밀번호가 일치하지 않습니다."));
        return jwtUtil.generateToken(user.getUsername());
    }
}
