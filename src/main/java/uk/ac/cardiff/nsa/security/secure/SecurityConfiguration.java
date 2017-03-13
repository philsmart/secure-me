package uk.ac.cardiff.nsa.security.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import uk.ac.cardiff.nsa.security.secure.auth.CustomUsernamePasswordAuthenticationHandler;

import javax.inject.Inject;

/**
 * Created by philsmart on 06/02/2017.
 */

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Inject
    private CustomUsernamePasswordAuthenticationHandler customProvider;


    @Autowired
    public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        log.debug("Setting up custom auth manager");
        auth.authenticationProvider(customProvider);


    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated().and().httpBasic();

    }
}




