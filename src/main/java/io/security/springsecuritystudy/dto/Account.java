package io.security.springsecuritystudy.dto;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

public record Account(String username, String password, List<GrantedAuthority> authorities) {
}
