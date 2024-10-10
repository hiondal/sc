package com.subride.sc.scg;

import com.subride.sc.scg.lb.ServiceDiscovery;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
@EnableDiscoveryClient
@Slf4j
public class ScgApplication {
    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(ScgApplication.class, args);
/*
        log.info("************* Get services **************");
        ServiceDiscovery serviceDiscovery = context.getBean(ServiceDiscovery.class);

        log.info("*** MEMBER-SERVICE ***");
        serviceDiscovery.getServiceInstances("member-service");

 */
    }
}
