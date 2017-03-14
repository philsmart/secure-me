package uk.ac.cardiff.nsa.security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by philsmart on 13/03/2017.
 */
@RestController
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    @RequestMapping(value = "/login", method= RequestMethod.GET, produces ="application/json" )
    public String login(HttpServletRequest request){

        log.info("Login request");

        Object auth = request.getHeader("Authorization");

        log.debug("Has auth header [{}]",auth);

        return  "token";


    }
}