package com.cybage.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.cybage.user.User;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {
	@Autowired
	private JwtTokenUtil jwtUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!hasAuthorizationBearer(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = getAccessToken(request);

		if (!jwtUtil.validateAccessToken(token)) {
			filterChain.doFilter(request, response);
			return;
		}

		setAuthenticationContext(token, request);
		filterChain.doFilter(request, response);
	}

	/*
	 * Bearer Tokens are the predominant type of access token used with OAuth 2.0. A
	 * Bearer Token is an opaque string, not intended to have any meaning to clients
	 * using it. Some servers will issue tokens that are a short string of
	 * hexadecimal characters, while others may use structured tokens such as JSON
	 * Web Tokens.
	 */
	//header.payload.signature
	private boolean hasAuthorizationBearer(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		if (ObjectUtils.isEmpty(header) || !header.startsWith("Bearer")) {
			return false;
		}

		return true;
	}

	private String getAccessToken(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		String token = header.split(" ")[1].trim();
		return token;
	}

	private void setAuthenticationContext(String token, HttpServletRequest request) {
		UserDetails userDetails = getUserDetails(token);

		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
				null);

		authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	private UserDetails getUserDetails(String token) {
		User userDetails = new User();
		String[] jwtSubject = jwtUtil.getSubject(token).split(",");

		userDetails.setId(Integer.parseInt(jwtSubject[0]));
		userDetails.setEmail(jwtSubject[1]);

		return userDetails;
	}
}
