package io.security.springsecuritystudy;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/home")
	public String home() {
		return "home";
	}

	@GetMapping("/loginPage")
	public String loginPage() {
		return "loginPage";
	}

	@GetMapping("/helloworld")
	public String helloworld() {
		return "Hello World";
	}

	@GetMapping("/security/test")
	public String security() {
		return "security";
	}

	@GetMapping("/anonymous")
	public String anonymous() {
		return "anonymous";
	}

	@GetMapping("/logoutSuccess")
	public String logoutSuccess() {
		return "logoutSuccess";
	}
}
