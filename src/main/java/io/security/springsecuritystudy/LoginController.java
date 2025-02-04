package io.security.springsecuritystudy;

import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class LoginController {
	private final AuthenticationManager authenticationManager;
	private final HttpSessionSecurityContextRepository sessionSecurityContextRepository = new HttpSessionSecurityContextRepository();

	public LoginController(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@PostMapping("/login")
	public Authentication login(@RequestBody LoginRequest login, HttpServletRequest request,
		HttpServletResponse response) {

		// 인증되지 않은 Authentication
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(
			login.username, login.password);

		//인증된 토큰
		Authentication authenticate = authenticationManager.authenticate(token);

		SecurityContext context = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
		context.setAuthentication(authenticate);
		SecurityContextHolder.getContextHolderStrategy().setContext(context);
		sessionSecurityContextRepository.saveContext(context, request, response);

		return authenticate;
	}

	public record LoginRequest(String username, String password) {
	}
}
