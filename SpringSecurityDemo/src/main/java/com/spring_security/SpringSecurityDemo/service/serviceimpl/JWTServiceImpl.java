package com.spring_security.SpringSecurityDemo.service.serviceimpl;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.spring_security.SpringSecurityDemo.entity.User;
import com.spring_security.SpringSecurityDemo.service.JWTService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JWTServiceImpl implements JWTService{
	
	private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

	@Override
	public String generateToken(UserDetails userDetails) {
		
		
		return Jwts.builder()
				   .setSubject(userDetails.getUsername())
				   .setIssuedAt(new Date(System.currentTimeMillis()))
				   .setExpiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 24))
				   .signWith(getSigninKey(), SignatureAlgorithm.HS256)
				   .compact();
		
	}
	
	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		
		final Claims claim = extractAllClaims(token);
		
		return claimsResolver.apply(claim);
	}

	private Claims extractAllClaims(String token) {
		
		return Jwts.parserBuilder().setSigningKey(getSigninKey()).build().parseClaimsJwt(token).getBody();
	}

	private Key getSigninKey() {
		byte[] key_bytes = Decoders.BASE64.decode(SECRET_KEY);
		
		return Keys.hmacShaKeyFor(key_bytes);
	}
	
	@Override
	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	@Override
	public boolean isTokenValid(String token, UserDetails userDetails) {
		
		final String username = extractUserName(token);
		
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		
		return extractClaim(token,Claims::getExpiration).before(new Date());
	}

	@Override
	public String generateRefreshToken(HashMap<String,Object> extraClaims, User user) {
		return Jwts.builder()
				   .setClaims(extraClaims)
				   .setSubject(user.getUsername())
				   .setIssuedAt(new Date(System.currentTimeMillis()))
				   .setExpiration(new Date(System.currentTimeMillis()+ 604800000))
				   .signWith(getSigninKey(), SignatureAlgorithm.HS256)
				   .compact();
	}
	
}
