package io.security.springsecuritystudy.config;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> {
			auth.requestMatchers("/security/**").authenticated();
			auth.requestMatchers("/anonymous").hasRole("GUEST");
			auth.requestMatchers("/**").permitAll();
		});
		http.formLogin(form -> form
			// .loginPage("/loginPage")
			.loginProcessingUrl("/loginProc")
			.defaultSuccessUrl("/", true) // successHandler 구현하면 구현한 로직 수행한다.
			.failureUrl("/failed") // failureHandler 구현하면 구현한 로직 수행한다.
			.usernameParameter("userId") //form의 id필드의 name명
			.passwordParameter("passwd") //formdml password필드의 name명
			// .successHandler((request, response, authentication) -> {
			// 	System.out.println("Authentication: " + authentication);
			// 	response.sendRedirect("/home");
			// })
			// .failureHandler((request, response, exception) -> {
			// 	System.out.println("exception: " + exception.getMessage());
			// 	response.sendRedirect("/loginPage");
			// })
			.permitAll()
		);

		// http.httpBasic(Customizer.withDefaults());

		//Remember-me
		// http.rememberMe(rememberMe -> {
		// 	// rememberMe.alwaysRemember(true);  //항상 rememberMe 여부
		// 	rememberMe.tokenValiditySeconds(3600); // 토큰유효기간 (초)
		// 	rememberMe.userDetailsService(this.userDetailsService());
		// 	rememberMe.rememberMeParameter("remember");
		// 	rememberMe.rememberMeCookieName("remember");
		// 	rememberMe.key("security");
		// });

		//Anonymous
		http.anonymous(anonymous -> anonymous
			.principal("guest")
			.authorities("ROLE_GUEST")
		);

		//Log out
		http.logout(logout -> logout
			.logoutUrl("/logout")
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
			.logoutSuccessUrl("/logoutSuccess")
			.logoutSuccessHandler(new LogoutSuccessHandler() {

				@Override
				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
					response.sendRedirect("/logoutSuccess");
				}
			})
			.deleteCookies("JSESSIONID", "remember-me")
			.invalidateHttpSession(true)
			.clearAuthentication(true)
			.addLogoutHandler(new LogoutHandler() {
				@Override
				public void logout(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) {
					HttpSession session = request.getSession();
					session.invalidate();
					SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
					SecurityContextHolder.getContextHolderStrategy().clearContext();
				}
			})
			.permitAll());

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withUsername("user")
			.password("{noop}1111")
			.roles("ROLES_USER")
			.build();
		return new InMemoryUserDetailsManager(user);
	}

}
