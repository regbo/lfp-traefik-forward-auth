package com.lfp.traefik.forwardauth.proxy;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.PropertySource;


@SpringBootApplication
@PropertySource({"classpath:application-dev-local.properties", "classpath:application.properties"})
public class DemoApplication implements CommandLineRunner {

    private static final Class<?> THIS_CLASS = new Object() {
    }.getClass().getEnclosingClass();

    public static void main(String[] args) {
        new SpringApplicationBuilder(THIS_CLASS).web(WebApplicationType.NONE).run(args);
    }

    @Override
    public void run(String... args) throws Exception {

    }


}
