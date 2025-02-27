package io.security.springsecuritystudy.config;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("customWebSecurity")
public class CustomWebSecurity {

	public boolean check(Authentication authentication) {
		return authentication.isAuthenticated();
	}
}
