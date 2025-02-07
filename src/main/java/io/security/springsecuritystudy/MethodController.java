package io.security.springsecuritystudy;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MethodController {

	@GetMapping("/admin")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public String admin() {
		return "admin";
	}

	@GetMapping("/user")
	@PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
	public String user() {
		return "user";
	}

	@GetMapping("/isAuthenticated")
	@PreAuthorize("isAuthenticated")
	public String isAuthenticated() {
		return "isAuthenticated";
	}

	@GetMapping("/user/{id}")
	@PreAuthorize("#id == authentication.name")
	public String authentication(@PathVariable String id) {
		return id;
	}

	@GetMapping("/owner")
	@PostAuthorize("returnObject.owner() == authentication.name")
	public User owner(String owner) {
		return new User(owner, false);
	}

	@GetMapping("/isSecure")
	@PostAuthorize("hasAuthority('ROLE_USER') and returnObject.secure")
	public User isSecure(String owner, String secure) {
		return new User(owner, "Y".equals(secure));
	}

	public record User(String owner, boolean isSecure) {}
}
