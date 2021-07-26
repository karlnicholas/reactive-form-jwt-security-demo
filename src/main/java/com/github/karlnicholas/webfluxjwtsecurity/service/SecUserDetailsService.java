package com.github.karlnicholas.webfluxjwtsecurity.service;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.github.karlnicholas.webfluxjwtsecurity.model.UserRepository;

import reactor.core.publisher.Mono;

@Component
public class SecUserDetailsService implements ReactiveUserDetailsService {

	private final UserRepository userRepository;
	
    public SecUserDetailsService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
    public Mono<UserDetails> findByUsername(String username) {
        return userRepository.findByUsername(username).map(UserDetails.class::cast);
    }
}