package com.spring_security.SpringSecurityDemo.service;

import com.spring_security.SpringSecurityDemo.dto.JwtAuthenticationResponse;
import com.spring_security.SpringSecurityDemo.dto.RefreshTokenRequest;
import com.spring_security.SpringSecurityDemo.dto.SignInRequest;
import com.spring_security.SpringSecurityDemo.dto.SignupRequest;
import com.spring_security.SpringSecurityDemo.entity.User;

public interface AuthenticationService {

	public User signup(SignupRequest signUpRequest);
	
	public JwtAuthenticationResponse signin(SignInRequest signin) throws IllegalAccessException;
	
	public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
