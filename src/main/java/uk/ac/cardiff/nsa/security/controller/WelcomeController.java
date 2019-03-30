package uk.ac.cardiff.nsa.security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by philsmart on 13/03/2017.
 */
@RestController
@RequestMapping("/api/")
public class WelcomeController {


    private static final Logger log = LoggerFactory.getLogger(WelcomeController.class);

    @RequestMapping(value = "/hi", method= RequestMethod.GET, produces ="application/json" )
    public String sayHello(){

        return  "HELLO WORLD";


    }


    @RequestMapping(value = "/admin", method = RequestMethod.GET, produces = "application/json")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String sayHelloToTheAdmin() {

        return "HELLO ADMIN";


    }
}
