package com.spring_security.SpringSecurityDemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.spring_security.SpringSecurityDemo.entity.Role;
import com.spring_security.SpringSecurityDemo.service.UserService;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	@Autowired
	private JwtAuthFilter jwtAuthFilter;
	
	@Autowired
	private UserService userService;
	
	
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http
			.csrf(AbstractHttpConfigurer::disable)
			.authorizeHttpRequests(request -> request.requestMatchers("/api/v1/auth/**")
													 .permitAll()
													 .requestMatchers("/api/v1/auth/admin").hasAnyAuthority(Role.ADMIN.name())
													 .requestMatchers("/api/v1/auth/user").hasAnyAuthority(Role.USER.name())
													 .anyRequest().authenticated())
			.sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authenticationProvider(authenticationProvider()).addFilterBefore( 
															 jwtAuthFilter,UsernamePasswordAuthenticationFilter.class );
									
			
			
		
		
		return http.build();
		
	}

    @Bean
    AuthenticationProvider authenticationProvider() {
		
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userService.userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		
		
		return authenticationProvider;
	}


    @Bean
    PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	@Bean
	UserDetailsService userDetailsService() {
		
		UserDetails parthiban = User.builder()
									.username("parthiban")
									.password(passwordEncoder().encode("parthiban"))
									.roles("USER")
									.build();
		
		UserDetails admin = User.builder()
								.username("admin")
								.password(passwordEncoder().encode("admin"))
								.roles("ADMIN")
								.build();
		
		
		return new InMemoryUserDetailsManager(parthiban,admin);
	}
}
