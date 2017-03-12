package uk.ac.cardiff.nsa.security.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by philsmart on 06/02/2017.
 */

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);


    @Autowired
    public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        log.debug("Setting up auth manager");


    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
//                .antMatcher("/api/v1/*").authorizeRequests().anyRequest().authenticated().and().httpBasic();

    }
}




