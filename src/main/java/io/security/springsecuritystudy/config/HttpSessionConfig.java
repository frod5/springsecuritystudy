package io.security.springsecuritystudy.config;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSession;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

@Configuration
@EnableSpringHttpSession
public class HttpSessionConfig {

	@Bean
	public CookieSerializer cookieSerializer() {
		DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
		cookieSerializer.setUseSecureCookie(true);
		cookieSerializer.setUseHttpOnlyCookie(true);
		cookieSerializer.setSameSite("Lax");
		return cookieSerializer;
	}

	@Bean
	public SessionRepository<MapSession> sessionRepository() {
		return new MapSessionRepository(new ConcurrentHashMap<>());
	}
}
