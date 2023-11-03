package com.odinbook.authserver;

import com.odinbook.authserver.config.LoginRecord;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@SpringBootApplication
@RestController
public class AuthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServerApplication.class, args);
	}

	@Autowired
	private AuthenticationManager authenticationManager;


	@GetMapping("/hello")
	public String hello(){
		System.out.println("Hello WOrld");
		return "Hello ,"+ SecurityContextHolder.getContext().getAuthentication().getName();
	}
	@PostMapping("/login")
	public String ts(@RequestBody LoginRecord loginRecord, HttpServletRequest request){

		System.out.println(loginRecord.userName());
		System.out.println(loginRecord.password());


		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRecord.userName(), loginRecord.password()
				)
		);


		System.out.println(authentication.isAuthenticated());

		if(authentication.isAuthenticated()) {
			SecurityContext sc = SecurityContextHolder.getContext();
			sc.setAuthentication(authentication);
			HttpSession session = request.getSession(true);
			session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);


			System.out.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
			System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());
			System.out.println(SecurityContextHolder.getContext().getAuthentication().getAuthorities());

		}

		return "Just Hi!!!!!!";
	}
	@GetMapping("/oauth2/code")
	public String code(@RequestParam String code){
		System.out.println(code);
		return code;
	}
}
