package com.spring_security.SpringSecurityDemo.service.serviceimpl;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring_security.SpringSecurityDemo.dto.JwtAuthenticationResponse;
import com.spring_security.SpringSecurityDemo.dto.RefreshTokenRequest;
import com.spring_security.SpringSecurityDemo.dto.SignInRequest;
import com.spring_security.SpringSecurityDemo.dto.SignupRequest;
import com.spring_security.SpringSecurityDemo.entity.Role;
import com.spring_security.SpringSecurityDemo.entity.User;
import com.spring_security.SpringSecurityDemo.repository.UserRepository;
import com.spring_security.SpringSecurityDemo.service.AuthenticationService;
import com.spring_security.SpringSecurityDemo.service.JWTService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService{

	@Autowired
	private final UserRepository userRepository = null;
	
	@Autowired
	private final PasswordEncoder passwordEncoder = null;
	
	@Autowired
	private final AuthenticationManager authenticationManager = null;
	
	@Autowired
	private final JWTService jwtService = null;
	
	@Override
	public User signup(SignupRequest signUpRequest) {
		User user = new User();
		
		user.setEmail(signUpRequest.getEmail());
		user.setFirstName(signUpRequest.getFirstName());
		user.setLastName(signUpRequest.getLastName());
		
		user.setRole(Role.USER);
		
		user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
		
		
		return userRepository.save(user);
	}
	
	@Override
	public JwtAuthenticationResponse signin(SignInRequest signin) throws IllegalAccessException {
		
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signin.getEmail(), signin.getPassword()));
		
		var user = userRepository.findByEmail(signin.getEmail()).orElseThrow(() -> new IllegalAccessException("User not found"));
		
		var jwt = jwtService.generateToken(user);
		
		var refreshToken = jwtService.generateRefreshToken(new HashMap<>(),user);
		
		JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
		
		jwtAuthenticationResponse.setToken(jwt);
		jwtAuthenticationResponse.setRefreshToken(refreshToken);
		
		return jwtAuthenticationResponse;
	}
	
	@Override
	public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
		
		String userEmail = jwtService.extractUserName(refreshTokenRequest.getToken());
		
		User user = userRepository.findByEmail(userEmail).orElseThrow();
		
		if(jwtService.isTokenValid(refreshTokenRequest.getToken(), user)) {
			var jwt = jwtService.generateToken(user);
			
			JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
			
			jwtAuthenticationResponse.setToken(jwt);
			jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
			
			return jwtAuthenticationResponse;
		}
		return null;
	}
	
	
}
