
package uk.ac.cardiff.nsa.security.secure;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import uk.ac.cardiff.nsa.security.secure.auth.OurBasicAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfiguration.class);

    @Override
    protected void configure(final HttpSecurity http) throws Exception {

        http.addFilterBefore(new OurBasicAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        http.authorizeRequests().anyRequest().authenticated();

    }
}
