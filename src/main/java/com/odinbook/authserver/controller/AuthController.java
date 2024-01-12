package com.odinbook.authserver.controller;



import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.odinbook.authserver.record.LoginRecord;
import com.odinbook.authserver.userDetails.CustomUserDetails;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
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

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRecord.email(), loginRecord.password()
                )
        );

        SecurityContext sc = SecurityContextHolder.getContext();
        sc.setAuthentication(authentication);
        HttpSession session = request.getSession(true);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);

        return ResponseEntity.ok().build();

    }

    @GetMapping("/getEmail")
    public String getEmail(){

        return SecurityContextHolder.getContext().getAuthentication().getName();
    }


    @GetMapping("/perform_logout")
    public ResponseEntity<?> logout(){

        CustomUserDetails userDetails =  (CustomUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();


        Optional.of(RequestContextHolder.currentRequestAttributes())
                .map(ServletRequestAttributes.class::cast)
                .map(ServletRequestAttributes::getRequest)
                .map(HttpServletRequest::getSession)
                .ifPresent(HttpSession::invalidate);

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
