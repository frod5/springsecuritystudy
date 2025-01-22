package io.security.springsecuritystudy.config;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.security.springsecuritystudy.dto.Account;

public class CustomUserDetails implements UserDetails {

	private final Account account;

	public CustomUserDetails(Account account) {
		this.account = account;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return account.authorities();
	}

	@Override
	public String getPassword() {
		return account.password();
	}

	@Override
	public String getUsername() {
		return account.username();
	}
}
