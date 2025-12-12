package com.temp.backend.global.exception;

import com.temp.backend.global.code.ErrorCode;
import lombok.Getter;

@Getter
public class MemberAlreadyExistsException extends RuntimeException {
    private final ErrorCode errorCode;

    public MemberAlreadyExistsException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
