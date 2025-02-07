package io.security.springsecuritystudy;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.security.springsecuritystudy.annotation.IsAdmin;
import io.security.springsecuritystudy.annotation.IsUser;
import io.security.springsecuritystudy.service.DataService;
import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;

@RestController
public class MethodController {

	private final DataService dataService;

	public MethodController(DataService dataService) {
		this.dataService = dataService;
	}

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

	@PostMapping("/writeList")
	public List<User> writeList(@RequestBody List<User> users) {
		return dataService.writeList(users);
	}

	@PostMapping("/writeMap")
	public Map<String, User> writeMap(@RequestBody List<User> users) {
		return dataService.writeMap(users.stream().collect(Collectors.toMap(user -> user.owner, user -> user)));
	}

	@GetMapping("/readList")
	public List<User> readList() {
		return dataService.readList();
	}

	@GetMapping("/readMap")
	public Map<String, User> readMap() {
		return dataService.readMap();
	}

	@GetMapping("/user/secured")
	@Secured("ROLE_USER")
	public String secured() {
		return "secured";
	}

	@GetMapping("/user/jsr")
	@RolesAllowed("USER")
	public String jsr() {
		return "jsr";
	}

	@GetMapping("/permitAll")
	@PermitAll
	public String permitAll() {
		return "permitAll";
	}

	@GetMapping("/denyAll")
	@DenyAll
	public String denyAll() {
		return "denyAll";
	}

	@GetMapping("/isUser")
	@IsUser
	public String isUser() {
		return "isUser";
	}

	@GetMapping("/isAdmin")
	@IsAdmin
	public String isAdmin() {
		return "isAdmin";
	}

	@GetMapping("/customIsUser")
	@PreAuthorize("@myAuthorizer.isUser(#root)")
	public String customIsUser() {
		return "customIsUser";
	}


	public record User(String owner, boolean isSecure) {
	}
}
