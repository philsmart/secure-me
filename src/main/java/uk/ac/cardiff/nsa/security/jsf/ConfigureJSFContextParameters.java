package uk.ac.cardiff.nsa.security.jsf;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Configuration;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * JSF configuration parameters registered to the {@link javax.servlet.Servlet}. @Component allows for spring boot configuration.
 */
@Configuration
public class ConfigureJSFContextParameters implements ServletContextInitializer {

    private static final Logger log = LoggerFactory.getLogger(ConfigureJSFContextParameters.class);

    @Override
    public void onStartup(final ServletContext servletContext) throws ServletException {
        log.info("Setting up JSF parameters");
        //Below is very important, it forces the faces context to load correctly if not using web.xml
        servletContext.setInitParameter("com.sun.faces.forceLoadConfiguration", "true");
        //servletContext.setInitParameter("javax.faces.DEFAULT_SUFFIX", ".xhtml");
        servletContext.setInitParameter("javax.faces.PARTIAL_STATE_SAVING_METHOD", "true");
        servletContext.setInitParameter("javax.faces.PROJECT_STAGE", "Development");
        servletContext.setInitParameter("facelets.DEVELOPMENT", "true");
        servletContext.setInitParameter("javax.faces.STATE_SAVING_METHOD", "server");

        servletContext.setInitParameter("javax.faces.FACELETS_REFRESH_PERIOD", "1");


    }
}
