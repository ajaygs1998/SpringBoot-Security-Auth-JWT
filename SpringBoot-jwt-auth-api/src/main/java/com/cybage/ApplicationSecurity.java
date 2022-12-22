package com.cybage;

//import javax.servlet.http.HttpServletResponse;
//
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//import com.cybage.jwt.JwtTokenFilter;
//import com.cybage.user.UserRepository;

//@EnableWebSecurity
//public class ApplicationSecurity extends WebSecurityConfigurerAdapter {
//
//	@Autowired
//	private UserRepository userRepo;
//
//	@Autowired
//	private JwtTokenFilter jwtTokenFilter;
//
//	@Override
//	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.userDetailsService(username -> userRepo.findByEmail(username)
//				.orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found.")));
//	}
//
//	@Bean
//	PasswordEncoder passwordEncoder() {
//		return new BCryptPasswordEncoder();
//	}
//
//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable();
//		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//
//		http.authorizeRequests().antMatchers("/auth/login").permitAll().anyRequest().authenticated();
//
//		http.exceptionHandling().authenticationEntryPoint((request, response, ex) -> {
//			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
//		});
//
//		http.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
//	}
//
//	@Override
//	@Bean
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		return super.authenticationManagerBean();
//	}
//	 
//}
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.cybage.jwt.JwtTokenFilter;
import com.cybage.user.UserRepository;

@Configuration
public class ApplicationSecurity {

	@Autowired
	private UserRepository userRepo;
	@Autowired
	private JwtTokenFilter jwtTokenFilter;

	@Bean
	public UserDetailsService userDetailsService() {
		return new UserDetailsService() {

			@Override
			public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
				return userRepo.findByEmail(username)
						.orElseThrow(() -> new UsernameNotFoundException("User " + username + " not found"));
			}
		};
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http
		.csrf()
		.disable()
		.sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.authorizeRequests()
		.antMatchers("/auth/login", "/docs/**", "/users")
		.permitAll()
		.anyRequest()
		.authenticated()
		.and()
		.exceptionHandling()
		.authenticationEntryPoint((request, response, ex) -> {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, ex.getMessage());
		})
		.and()
		.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}
