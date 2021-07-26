package com.github.karlnicholas.webfluxjwtsecurity.controller;

import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import com.github.karlnicholas.webfluxjwtsecurity.dto.UserDto;
import com.github.karlnicholas.webfluxjwtsecurity.dto.mapper.UserMapper;
import com.github.karlnicholas.webfluxjwtsecurity.service.UserService;

import reactor.core.publisher.Mono;

@Component
public class PublicHandler {
    private final UserService userService;
    private final UserMapper userMapper;

    public PublicHandler(UserService userService, UserMapper userMapper) {
        this.userService = userService;
        this.userMapper = userMapper;
    }

	public Mono<ServerResponse> handleDemoUser(ServerRequest serverRequest) {
		return ServerResponse.ok().body(serverRequest.bodyToMono(UserDto.class)
				.map(userMapper::mapToDto)
				.flatMap(userService::createUser)
				.map(userMapper::mapToUser), UserDto.class);
	}
	public Mono<ServerResponse> handleVersion(ServerRequest serverRequest) {
		return ServerResponse.ok().bodyValue("Verion 1.0.0");
	}

}
