package com.temp.backend.global.exception;

import com.temp.backend.global.code.ErrorCode;
import com.temp.backend.global.exception.dto.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MemberAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleMemberAlreadyExistsException(MemberAlreadyExistsException ex) {
        ErrorResponse response = new ErrorResponse(ex.getErrorCode());
        return new ResponseEntity<>(response, ex.getErrorCode().getStatus());
    }

    @ExceptionHandler(JwtKeyLoadException.class)
    public ResponseEntity<ErrorResponse> handleJwtKeyLoadException(JwtKeyLoadException ex) {
        ErrorResponse response = new ErrorResponse(ex.getErrorCode());
        ex.printStackTrace();
        return new ResponseEntity<>(response, ex.getErrorCode().getStatus());
    }

    @ExceptionHandler({UsernameNotFoundException.class, BadCredentialsException.class})
    public ResponseEntity<ErrorResponse> handleAuthenticationException(Exception ex) {
        ErrorResponse response = new ErrorResponse(ErrorCode.MEMBER_NOT_FOUND);
        ex.printStackTrace();
        return new ResponseEntity<>(response, ErrorCode.MEMBER_NOT_FOUND.getStatus());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        ErrorResponse response = new ErrorResponse(ErrorCode.INTERNAL_SERVER_ERROR);
        ex.printStackTrace();
        return new ResponseEntity<>(response, ErrorCode.INTERNAL_SERVER_ERROR.getStatus());
    }
}
