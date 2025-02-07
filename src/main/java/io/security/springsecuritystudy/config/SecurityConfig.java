package io.security.springsecuritystudy.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

// @EnableWebSecurity
// @Configuration
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {

		// DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
		// expressionHandler.setApplicationContext(context);
		//
		// WebExpressionAuthorizationManager autorizationManager = new WebExpressionAuthorizationManager("@customWebSecurity.check(authentication, request)");

		http.authorizeHttpRequests(auth -> {
			auth.requestMatchers("/security/**").authenticated();
			auth.requestMatchers("/anonymous").hasRole("GUEST");

			//custom 표현식
			// auth.requestMatchers("/user/{name}").access(new WebExpressionAuthorizationManager("#name == authentication.name"));
			// auth.requestMatchers("/resource/db").access(new WebExpressionAuthorizationManager("hasAuthority('ROLE_DB') or hasAuthority('ROLE_ADMIN')"));
			// auth.requestMatchers("/custom/test").access(autorizationManager);
			// auth.requestMatchers(new CustomRequestMatcher("/custom/test2")).hasRole("GUEST");

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

		//request cache
		// http.requestCache()

		// AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
		// AuthenticationManager authenticationManager = builder.build();
		// AuthenticationManager authenticationManager1 = builder.getObject();
		//
		// http.addFilterBefore(this.customAuthenticationFilter(http, authenticationManager1), UsernamePasswordAuthenticationFilter.class);

		// http.addFilterBefore(customAuthenticationFilter(http), UsernamePasswordAuthenticationFilter.class);

		http.csrf(AbstractHttpConfigurer::disable);

		// 동시 세션 제어
		http.sessionManagement(session -> session
			// .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 생성 전략
			// .sessionFixation(sessionFixation -> {sessionFixation.changeSessionId();}) 세션 고정 공격 보호 default changeSessionId()
			.invalidSessionUrl("/invalidSessionUrl")
			.maximumSessions(1)
			.maxSessionsPreventsLogin(false)  // false -> 마지막 사용자 세션만료, true 초과 세션 요청 시 인증 차단.
			.expiredUrl("/expiredUrl")
		);

		http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

		// http.exceptionHandling(exception -> {
		// 	exception.authenticationEntryPoint(new AuthenticationEntryPoint() {
		// 		@Override
		// 		public void commence(HttpServletRequest request, HttpServletResponse response,
		// 			AuthenticationException authException) throws IOException, ServletException {
		// 			System.out.println(authException.getMessage());
		// 			response.sendRedirect("/login"); // 시큐리티가 로그인페이지를 만들어주지 않음.
		// 		}
		// 	});
		// 	exception.accessDeniedHandler(new AccessDeniedHandler() {
		// 		@Override
		// 		public void handle(HttpServletRequest request, HttpServletResponse response,
		// 			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		// 			System.out.println(accessDeniedException.getMessage());
		// 			response.sendRedirect("/denied");
		// 		}
		// 	});
		// });

		//csrf
		http.csrf(AbstractHttpConfigurer::disable);


		return http.build();
	}

	@Bean
	@Order(1)
	public SecurityFilterChain securityFilterChain2(HttpSecurity http, ApplicationContext context) throws Exception {

		http.securityMatchers(matchers -> matchers.requestMatchers("/api/**", "/oauth/**"));
		http.authorizeHttpRequests(auth -> {
			auth.anyRequest().permitAll();
		});

		return http.build();
	}

	// public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
	// 	CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
	// 	customAuthenticationFilter.setAuthenticationManager(authenticationManager);
	// 	return customAuthenticationFilter;
	// }

	// public CustomAuthenticationFilter customAuthenticationFilter(HttpSecurity http) {
	// 	List<AuthenticationProvider> providers1 = List.of(new DaoAuthenticationProvider());
	// 	ProviderManager parent = new ProviderManager(providers1);
	// 	List<AuthenticationProvider> providers2 = List.of(new CustomAuthenticationProvider());
	// 	ProviderManager providerManager = new ProviderManager(providers2, parent);
	//
	// 	CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(http);
	// 	customAuthenticationFilter.setAuthenticationManager(providerManager);
	// 	return customAuthenticationFilter;
	// }



	/*@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user = User.withUsername("user")
			.password("{noop}1111")
			.roles("ROLES_USER")
			.build();
		return new InMemoryUserDetailsManager(user);
	}*/

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.addAllowedOrigin("http://localhost:8080");
		configuration.addAllowedOrigin("http://localhost:3000");
		configuration.addAllowedHeader("*");
		configuration.addAllowedMethod("*");
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}

}
