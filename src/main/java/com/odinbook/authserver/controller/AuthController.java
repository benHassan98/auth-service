package com.odinbook.authserver.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.odinbook.authserver.record.LoginRecord;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.apache.tomcat.util.json.JSONParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.TreeMap;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@RestController
public class AuthController {

    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    @PostMapping("/perform_login")
    public ResponseEntity<?> login(@RequestBody LoginRecord loginRecord, HttpServletRequest request) throws AuthenticationException{


        System.out.println(loginRecord.email());
        System.out.println(loginRecord.password());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRecord.email(), loginRecord.password()
                )
        );

        System.out.println(authentication.isAuthenticated());

        SecurityContext sc = SecurityContextHolder.getContext();
        sc.setAuthentication(authentication);
        HttpSession session = request.getSession(true);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);

        return ResponseEntity.ok().build();

    }

    @GetMapping("/getEmail")
    public String getEmail(){

        System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());


        return SecurityContextHolder.getContext().getAuthentication().getName();
    }


    @GetMapping("/perform_logout")
    public ResponseEntity<?> logout(){

        SecurityContextHolder.clearContext();

        return ResponseEntity.ok().build();
    }

    @ExceptionHandler(value = AuthenticationException.class)
    public ResponseEntity<String> authenticationExceptionHandler(AuthenticationException exception) {

        TreeMap<String, String> treeMap = new TreeMap<>();
        treeMap.put("error",exception.getMessage());

        String json = JSONObjectUtils.toJSONString(treeMap);
        return ResponseEntity.status(HttpStatusCode.valueOf(401)).body(json);
    }

}
