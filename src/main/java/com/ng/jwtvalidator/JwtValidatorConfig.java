package com.ng.jwtvalidator;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan
public class JwtValidatorConfig {
	@Bean
    public JwtAuthorizationFilter JwtAuthorizationFilter() {
        return new JwtAuthorizationFilter();
    }

}
