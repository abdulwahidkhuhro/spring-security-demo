package com.learning.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {
	
	SecurityFilterChain defaulSecurityFilterChain(HttpSecurity http) throws Exception{
		
		http
			.authorizeHttpRequests(
					(authorize) -> authorize.anyRequest()
											.authenticated())
			.httpBasic(Customizer.withDefaults());
		
		return http.build();
	}
}
