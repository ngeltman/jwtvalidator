package com.ng.jwtvalidator;


import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtService {
    private static final int EXPIRATION_TIME = 1000 * 60 ;
    private static final String AUTHORITIES = "authorities";
    private final String SECRET_KEY;
 
    public JwtService() {
        SECRET_KEY = Base64.getEncoder().encodeToString("key".getBytes());
    }
 
    public String createToken(UserDetails userDetails) {
        String username = userDetails.getUsername();
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        return Jwts.builder()
                .setSubject(username)
                .claim(AUTHORITIES, authorities)
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }
 
    public Boolean hasTokenExpired(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody()
                .getExpiration()
                .before(new Date());
    }
 
    public Boolean validateToken(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return (userDetails.getUsername().equals(username) && !hasTokenExpired(token));
 
    }
 
    public String extractUsername(String token) {
    	
        return 
        		Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
 
    public Collection<? extends GrantedAuthority> getAuthorities(String token) {
        Claims claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
        ArrayList aus=(ArrayList)claims.get(AUTHORITIES);
        Iterator it=aus.iterator();
        Set s=new HashSet();
        while(it.hasNext()) {
        	LinkedHashMap lhm=(LinkedHashMap)it.next();
        	s.add(new SimpleGrantedAuthority((String)lhm.get("authority")));
        }
        
        return (Collection<? extends GrantedAuthority>) s ;
    }
}
