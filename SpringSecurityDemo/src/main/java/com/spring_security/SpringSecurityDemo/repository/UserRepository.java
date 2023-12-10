package com.spring_security.SpringSecurityDemo.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.spring_security.SpringSecurityDemo.entity.Role;
import com.spring_security.SpringSecurityDemo.entity.User;

public interface UserRepository extends JpaRepository<User, Long>{

	Optional<User> findByEmail(String username);
	
	User findByRole(Role role);

}
