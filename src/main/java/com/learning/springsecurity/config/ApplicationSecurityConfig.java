package com.learning.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.learning.springsecurity.security.ApplicationUserRole;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig {
	
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}
	
	@Bean
	SecurityFilterChain defaulSecurityFilterChain(HttpSecurity http) throws Exception{
		
		http.csrf().disable()
			.authorizeHttpRequests(
					(authorize) -> authorize.requestMatchers("/api/**")
											.hasRole(ApplicationUserRole.STUDENT.name())
											.anyRequest()
											.authenticated()
											)
			.httpBasic(Customizer.withDefaults());
		
		return http.build();
	}
	
	
	@Bean
	protected UserDetailsService userDetailsService() {
		
		UserDetails annaSmithUser = User.builder()
											 .username("annasmith")
											 .password(passwordEncoder.encode("password"))
											 .roles(ApplicationUserRole.STUDENT.name())
											 .build();
		
		UserDetails wahidUser = User.builder()
											.username("wahid")
											.password(passwordEncoder.encode("4244"))
											.roles(ApplicationUserRole.ADMIN.name())
											.build();
		
		UserDetails jameelUser = User.builder()
				.username("jameel")
				.password(passwordEncoder.encode("4244"))
				.roles(ApplicationUserRole.ADMINTRAINEE.name())
				.build();
		
		return new InMemoryUserDetailsManager(
				annaSmithUser,
				wahidUser,
				jameelUser
				);
	}
}
