package io.security.springsecuritystudy;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.security.springsecuritystudy.service.DataService;

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

	public record User(String owner, boolean isSecure) {
	}
}
