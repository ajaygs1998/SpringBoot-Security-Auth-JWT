package com.cybaage;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity(debug = true)
public class AppSecurityConfig  extends WebSecurityConfigurerAdapter { 
	
}
