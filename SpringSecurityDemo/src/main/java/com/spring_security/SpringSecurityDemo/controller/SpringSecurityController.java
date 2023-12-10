package com.spring_security.SpringSecurityDemo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring_security.SpringSecurityDemo.dto.JwtAuthenticationResponse;
import com.spring_security.SpringSecurityDemo.dto.RefreshTokenRequest;
import com.spring_security.SpringSecurityDemo.dto.SignInRequest;
import com.spring_security.SpringSecurityDemo.dto.SignupRequest;
import com.spring_security.SpringSecurityDemo.entity.User;
import com.spring_security.SpringSecurityDemo.service.AuthenticationService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class SpringSecurityController {

	@Autowired
	private final AuthenticationService authService = null;
			
	@PostMapping("/signup")
	public ResponseEntity<User> signUp(@RequestBody SignupRequest signUpRequest){
			return ResponseEntity.ok(authService.signup(signUpRequest));
	}

	@PostMapping("/signin")
	public ResponseEntity<JwtAuthenticationResponse> signin(@RequestBody SignInRequest signInRequest) throws IllegalAccessException{
		return ResponseEntity.ok(authService.signin(signInRequest));
	}
	
	@PostMapping("/refresh")
	public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) throws IllegalAccessException{
		return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
	}
}
