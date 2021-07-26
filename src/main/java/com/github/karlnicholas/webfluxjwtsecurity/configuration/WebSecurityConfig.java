package com.github.karlnicholas.webfluxjwtsecurity.configuration;

import java.util.Arrays;
import java.util.Optional;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import com.github.karlnicholas.webfluxjwtsecurity.service.UserService;
import com.nimbusds.jose.JOSEException;

import reactor.core.publisher.Mono;

/**
 * WebSecurityConfig class
 *
 * @author Erik Amaru Ortiz
 * @author Karl Nicholas
 */
@Configuration
@EnableReactiveMethodSecurity
public class WebSecurityConfig {
    private final Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);
    private final UserService userService;

    private final byte[] sharedSecret;
    @Value("${app.public_routes}")
    private String[] publicRoutes;
    
    public WebSecurityConfig(byte[] sharedSecret, UserService userService) {
    	this.sharedSecret = sharedSecret;
        this.userService = userService;
    }


    @Bean
    public CorsConfigurationSource corsConfiguration() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.applyPermitDefaultValues();
        corsConfig.addAllowedMethod(HttpMethod.PUT);
        corsConfig.addAllowedMethod(HttpMethod.DELETE);
        corsConfig.setAllowedOrigins(Arrays.asList("http://localhost:3000"));

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }
    
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) throws JOSEException {
        return http
        		.requestCache()
        	    .requestCache(NoOpServerRequestCache.getInstance())
        	    .and().securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                // don't create session
                .authorizeExchange()
                    .pathMatchers(HttpMethod.OPTIONS)
                        .permitAll()
                    .pathMatchers(publicRoutes)
                        .permitAll()
                    .pathMatchers( "/favicon.ico")
                        .permitAll()
                    .anyExchange()
                    	.permitAll()
                    .and()
                .csrf()
                    .disable()
                .httpBasic()
                    .disable()
//                .formLogin()
//                	.disable()
//                	.authenticationSuccessHandler(addCookie())
//                    .loginPage("/login")
//            	.and()
//                    .logout(logout -> logout.requiresLogout(new PathPatternParserServerWebExchangeMatcher("/auth/logout")))
                .exceptionHandling()
                    .authenticationEntryPoint((swe, e) -> {
                        logger.info("[1] Authentication error: Unauthorized[401]: " + e.getMessage());

                        return Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED));
                    })
                    .accessDeniedHandler((swe, e) -> {
                        logger.info("[2] Authentication error: Access Denied[401]: " + e.getMessage());

                        return Mono.fromRunnable(() -> swe.getResponse().setStatusCode(HttpStatus.FORBIDDEN));
                    })
                .and()
//                .addFilterAt(createAuthenticationFilter(authManager, AppServerAuthenticationConverter::getCookieToken), SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    AuthenticationWebFilter createAuthenticationFilter(ReactiveAuthenticationManager authManager, Function<ServerWebExchange, Optional<String>> extractTokenFunction) throws JOSEException {
        AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(authManager);
        authenticationFilter.setServerAuthenticationConverter( new AppServerAuthenticationConverter(sharedSecret, extractTokenFunction));
        authenticationFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/api/**"));
        return authenticationFilter;
    }

//    @Bean
//    public ReactiveAuthenticationManager authenticationManager() {
//    	return new ReactiveAuthenticationManager() {
//			@Override
//			public Mono<Authentication> authenticate(Authentication authentication) {
//				return userService.getUser((String)authentication.getPrincipal())
//                    .filter(user -> user.isEnabled())
//                    .switchIfEmpty(Mono.error(new AccountLockedException ("User account is disabled.")))
//                    .map(user -> authentication);
//			}
//    	};
//    }
    
    private ServerAuthenticationSuccessHandler addCookie() {
    	return new ServerAuthenticationSuccessHandler() {

			@Override
			public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
				webFilterExchange.getExchange().getResponse().addCookie(ResponseCookie.from("CCC", "CCC").build());
				
				// TODO Auto-generated method stub
				return Mono.empty().then();
			}
		};
    }

}
