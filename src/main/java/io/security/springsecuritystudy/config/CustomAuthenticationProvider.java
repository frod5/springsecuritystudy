package io.security.springsecuritystudy.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import io.security.springsecuritystudy.service.UserService;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final UserService userService;

	public CustomAuthenticationProvider(UserService userService) {
		this.userService = userService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String loginId = authentication.getName();
		String password = (String) authentication.getCredentials();

		//id 검증
		UserDetails user = userService.loadUserByUsername(loginId);

		if (user == null) {
			throw new UsernameNotFoundException("Username not found");
		}

		return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}
}