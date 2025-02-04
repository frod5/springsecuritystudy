package io.security.springsecuritystudy;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
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

	@GetMapping("/security/holder")
	public String securityHolder() {
		SecurityContext context = SecurityContextHolder.getContextHolderStrategy().getContext();
		Authentication authentication = context.getAuthentication();
		System.out.println(authentication);
		return "securityHolder";
	}

	@GetMapping("/anonymous")
	public String anonymous() {
		return "anonymous";
	}

	@GetMapping("/logoutSuccess")
	public String logoutSuccess() {
		return "logoutSuccess";
	}

	@GetMapping("/invalidSessionUrl")
	public String invalidSessionUrl() {
		return "invalidSessionUrl";
	}

	@GetMapping("/expiredUrl")
	public String expiredUrl() {
		return "expiredUrl";
	}

	@GetMapping("/denied")
	public String denied() {
		return "denied";
	}
}
