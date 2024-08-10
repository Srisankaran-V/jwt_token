package com.security.drugInventory.config;
import com.fasterxml.jackson.databind.ObjectMapper;  // Make sure to import ObjectMapper
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;
    private final ObjectMapper objectMapper; // Add ObjectMapper for serialization

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authorizationHeader.substring(7);
        String userEmail = null;
        try {
            userEmail = jwtService.extractEmail(jwt);
        } catch (RuntimeException e) {
            ErrorResponse errorResponse = ErrorResponse.builder()
                    .error("Unauthorized")
                    .message("Invalid JWT token")
                    .build();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
            return;
        }

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = null;
            try {
                userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            } catch (RuntimeException e) {
                ErrorResponse errorResponse = ErrorResponse.builder()
                        .error("Unauthorized")
                        .message("User not found")
                        .build();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
                return;
            }

            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                ErrorResponse errorResponse = ErrorResponse.builder()
                        .error("Unauthorized")
                        .message("Invalid JWT token")
                        .build();
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
//
//package com.security.drugInventory.config;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//@RequiredArgsConstructor
//public class JWTAuthenticationFilter extends OncePerRequestFilter {
//
//    private final JWTService jwtService;
//    private final UserDetailsService userDetailsService;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//
//        final String authorizationHeader = request.getHeader("Authorization");
//
//        // Check if Authorization header is present and starts with "Bearer "
//        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        final String jwt = authorizationHeader.substring(7);
//        String userEmail = null;
//        try {
//            userEmail = jwtService.extractEmail(jwt);
//        } catch (Exception e) {
//            // Handle invalid JWT token
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
//            return;
//        }
//
//        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails userDetails = null;
//            try {
//                userDetails = this.userDetailsService.loadUserByUsername(userEmail);
//            } catch (Exception e) {
//                // Handle user not found or other issues
//                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found");
//                return;
//            }
//
//            if (jwtService.isTokenValid(jwt, userDetails)) {
//                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                        userDetails,
//                        null,
//                        userDetails.getAuthorities());
//                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(authToken);
//            } else {
//                // Handle invalid token
//                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");
//                return;
//            }
//        }
//
//        filterChain.doFilter(request, response);
//    }
//}
