package com.filters;

import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.io.IOException;
import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class LoggingFilter extends OncePerRequestFilter {

	@Autowired
	private JwtService jwtService;

	private static final String MDC_KEY = "username";

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {

		long start = System.currentTimeMillis();
		MDC.put(MDC_KEY, getUsername(request));

		try {
			try {
				filterChain.doFilter(request, response);
			} catch (java.io.IOException | ServletException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} finally {
			long time = System.currentTimeMillis() - start;
//			log.info("Request {} {} completed in {} ms", request.getMethod(), request.getRequestURI(), time);
		

			MDC.remove(MDC_KEY);
		}
	}

	private String getUsername(HttpServletRequest request) {
		try {
			String header = request.getHeader("Authorization");
			String token = header.substring(7);

			Claims claims = jwtService.extractClaims(token);
			return claims.getSubject();

		} catch (Exception e) {
			return "anonymous";
		}
	}
}