package com.temp.backend.global.code;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // Auth
    MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND, "이메일 또는 비밀번호가 일치하지 않습니다."),
    MEMBER_ALREADY_EXIST(HttpStatus.CONFLICT, "이미 가입된 회원입니다."),

    // Jwt
    JWT_KEY_LOAD_FAILED(HttpStatus.INTERNAL_SERVER_ERROR, "JWT 키 로드에 실패했습니다."),

    // Common
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다.");

    private final HttpStatus status;
    private final String message;
}
