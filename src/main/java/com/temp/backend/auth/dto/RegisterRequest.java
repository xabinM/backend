package com.temp.backend.auth.dto;

import com.temp.backend.domain.user.entity.Role;
import lombok.Data;

@Data
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;
    private Role role;
}
