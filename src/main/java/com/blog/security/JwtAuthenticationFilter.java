package com.blog.security;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private JwtTokenHelper jwtTokenHelper;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
//		1.get Token
		String requestToken = request.getHeader("Authorization");
		if(StringUtils.hasText(requestToken) && requestToken.startsWith("Bearer ")) {
			String token=requestToken.substring(7);
		
			
//		// Bearer 2352523dgsg
//		System.out.println(requestToken);
//
//		String username = null;
//		String token = null;
//		if (request != null && requestToken.startsWith("Bearer ")) {
//			token = requestToken.substring(7);
//			try {
//				username = this.jwtTokenHelper.getUsernameFromToken(token);
//			} catch (IllegalArgumentException e) {
//				System.out.println("Unable to get Jwt token");
//			} catch (ExpiredJwtException e) {
//				System.out.println("Jwt token has expired");
//			} catch (MalformedJwtException e) {
//				System.out.println("Invalid Jwt Exception");
//			}
//
//		} else {
//			System.out.println("Jwt token does not Begin with Bearer");
//		}

		// once we get the token , now validate

//		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//			UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
//
//			if (this.jwtTokenHelper.validateToken(token, userDetails)) {
//				// sahi chal raha hai
//				// authentication karna hai
//				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//						userDetails, null, userDetails.getAuthorities());
//				usernamePasswordAuthenticationToken
//						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//
//				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//			} else {
//				System.out.println("invalid jwt token");
//			}
//
//		} else {
//			System.out.println("username is null or context is not null");
//		}
		
		try {
            // Validate the JWT token
            String username = jwtTokenHelper.getUsernameFromToken(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtTokenHelper.validateToken(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        } catch (Exception e) {
            // Handle JWT validation exceptions here
            System.out.println("JWT token validation failed: " + e.getMessage());
        }
    }
	
		filterChain.doFilter(request, response);
	}
}

