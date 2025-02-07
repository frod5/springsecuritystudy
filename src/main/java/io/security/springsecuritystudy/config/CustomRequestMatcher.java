package io.security.springsecuritystudy.config;

import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.http.HttpServletRequest;

public class CustomRequestMatcher implements RequestMatcher {

	private final String urlPattern;

	public CustomRequestMatcher(String urlPattern) {
		this.urlPattern = urlPattern;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		String uri = request.getRequestURI();
		return uri.startsWith(urlPattern);
	}
}
