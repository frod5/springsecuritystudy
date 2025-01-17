package io.security.springsecuritystudy;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

	@GetMapping("/")
	public String index() {
		return "index";
	}

	@GetMapping("/helloworld")
	public String helloworld() {
		return "Hello World";
	}

	@GetMapping("/security/test")
	public String security() {
		return "security";
	}
}
