package io.security.springsecuritystudy.service;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.security.springsecuritystudy.config.CustomUserDetails;
import io.security.springsecuritystudy.dto.Account;

@Service
public class UserService implements UserDetailsService {
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return new CustomUserDetails(
			new Account("user", "{noop}1111", List.of(new SimpleGrantedAuthority("ROLE_USER"))));
	}
}
