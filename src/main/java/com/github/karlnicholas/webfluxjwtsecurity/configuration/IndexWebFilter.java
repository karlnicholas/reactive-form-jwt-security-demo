package com.github.karlnicholas.webfluxjwtsecurity.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

@Component
public class IndexWebFilter implements WebFilter {
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    if (exchange.getRequest().getURI().getPath().equals("/")) {
        return chain.filter(exchange.mutate().request(exchange.getRequest().mutate().path("/index.html").build()).build());
    }
    if (exchange.getRequest().getURI().getPath().equals("/login") && exchange.getRequest().getMethod().compareTo(HttpMethod.GET) == 0 ) {
        return chain.filter(exchange.mutate().request(exchange.getRequest().mutate().path("/login.html").build()).build());
    }

    return chain.filter(exchange);
  }
}