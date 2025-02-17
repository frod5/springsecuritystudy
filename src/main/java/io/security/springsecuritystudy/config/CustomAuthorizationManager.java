package io.security.springsecuritystudy.config;

import java.util.function.Supplier;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class CustomAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

	private static final String REQUIRED_ROLE_PREFIX = "ROLE_SECURE";

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		Authentication auth = authentication.get();

		if(auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
			return new AuthorizationDecision(false);
		}

		boolean hasRole = auth.getAuthorities()
			.stream()
			.anyMatch(authority -> REQUIRED_ROLE_PREFIX.equals(authority.getAuthority()));

		return new AuthorizationDecision(hasRole);
	}
}
