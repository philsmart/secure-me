package uk.ac.cardiff.nsa.security.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import uk.ac.cardiff.nsa.security.secure.auth.CustomTokenAuthenticationFilter;
import uk.ac.cardiff.nsa.security.secure.auth.CustomUsernamePasswordAuthenticationProvider;

import javax.inject.Inject;

/**
 * Created by philsmart on 06/02/2017.
 */

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Inject
    private CustomUsernamePasswordAuthenticationProvider customProvider;


    private CustomTokenAuthenticationFilter tokenFilter = new CustomTokenAuthenticationFilter();


    @Autowired
    public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        log.debug("Setting up custom auth manager");
       // auth.authenticationProvider(customProvider);


    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().csrf().disable().addFilterBefore(tokenFilter,UsernamePasswordAuthenticationFilter.class).authorizeRequests().antMatchers("/api/**").authenticated();
        //http.authorizeRequests().anyRequest().permitAll();
    }
}




