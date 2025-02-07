package io.security.springsecuritystudy.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import io.security.springsecuritystudy.MethodController;

@Service
public class DataService {

	@PreFilter("filterObject.owner() == authentication.name")
	public List<MethodController.User> writeList(List<MethodController.User> users) {
		return users;
	}

	@PreFilter("filterObject.value.owner() == authentication.name")
	public Map<String, MethodController.User> writeMap(Map<String, MethodController.User> users) {
		return users;
	}

	@PostFilter("filterObject.owner() == authentication.name")
	public List<MethodController.User> readList() {
		return List.of(
			new MethodController.User("user", false),
			new MethodController.User("user2", false));
	}

	@PostFilter("filterObject.value.owner() == authentication.name")
	public Map<String, MethodController.User> readMap() {
		return new HashMap<>(Map.of(
			"user", new MethodController.User("user", true),
			"user2", new MethodController.User("user2", true)
		));
	}
}
