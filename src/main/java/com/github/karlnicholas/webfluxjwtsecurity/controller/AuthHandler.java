package com.github.karlnicholas.webfluxjwtsecurity.controller;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import com.github.karlnicholas.webfluxjwtsecurity.dto.AuthResultDto;
import com.github.karlnicholas.webfluxjwtsecurity.dto.UserLoginDto;
import com.github.karlnicholas.webfluxjwtsecurity.service.AuthService;

import reactor.core.publisher.Mono;

@Component
public class AuthHandler {
    private final AuthService authService;

    public AuthHandler(AuthService authService) {
        this.authService = authService;
    }

	public Mono<ServerResponse> handleLogin(ServerRequest serverRequest) {
		return ServerResponse.ok().build((exchange, context)->{
			return authService.authenticate(exchange.getFormData()).map(authResult->{
				exchange.getResponse().addCookie(ResponseCookie.from("token", authResult.getToken()).build());
				return authResult;
			}).then();
		});
	}
	public Mono<ServerResponse> handleLogout(ServerRequest serverRequest) {
		return ServerResponse.ok().build();
	}
}
