package com.temp.backend.global.exception;

import com.temp.backend.global.code.ErrorCode;
import lombok.Getter;

@Getter
public class JwtKeyLoadException extends RuntimeException {

    private final ErrorCode errorCode;

    public JwtKeyLoadException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    public JwtKeyLoadException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getMessage(), cause);
        this.errorCode = errorCode;
    }
}
