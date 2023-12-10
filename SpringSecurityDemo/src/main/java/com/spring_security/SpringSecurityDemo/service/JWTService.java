package com.spring_security.SpringSecurityDemo.service;

import java.util.HashMap;

import org.springframework.security.core.userdetails.UserDetails;

import com.spring_security.SpringSecurityDemo.entity.User;

public interface JWTService {

	public String extractUserName(String token);
	
	public String generateToken(UserDetails userDetails);
	
	public boolean isTokenValid(String token, UserDetails userDetails);

	public String generateRefreshToken(HashMap<String,Object> hashMap, User user);
	
}
