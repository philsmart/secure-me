package uk.ac.cardiff.nsa.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;

import javax.faces.webapp.FacesServlet;

@SpringBootApplication
public class SecureMeApplication {

    public static void main(String[] args) {


        SpringApplication.run(SecureMeApplication.class, args);
    }


    /**
     * Register the {@link FacesServlet} within the current {@link org.springframework.boot.web.servlet.ServletContextInitializer},
     * and hence with the v3 {@link javax.servlet.Servlet} provider. This maps all URL patterns *.xhtml to the {@link FacesServlet}.
     *
     * @return a {@link ServletRegistrationBean} with registered {@link FacesServlet}
     */
    @Bean
    public ServletRegistrationBean servletRegistrationBean() {
        final FacesServlet servlet = new FacesServlet();

        final ServletRegistrationBean servletRegistrationBean = new ServletRegistrationBean(servlet, new String[]{"*.xhtml"});
        servletRegistrationBean.setName("FacesServlet");
        servletRegistrationBean.setLoadOnStartup(1);

        return servletRegistrationBean;
    }


}
