package com.esqobar.demosecurity3;

import com.esqobar.demosecurity3.entities.Role;
import com.esqobar.demosecurity3.payloads.RegisterRequest;
import com.esqobar.demosecurity3.services.AuthService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class DemoSecurity3Application {

    public static void main(String[] args) {
        SpringApplication.run(DemoSecurity3Application.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthService service){
       return args -> {
           var admin = RegisterRequest.builder()
                   .firstname("Admin")
                   .lastname("Admin")
                   .email("admin@gmail.com")
                   .password("123456")
                   .role(Role.ADMIN)
                   .build();
           System.out.println("Admin Token: " + service.register(admin).getAccessToken());

           var manager = RegisterRequest.builder()
                   .firstname("Manager")
                   .lastname("Manager")
                   .email("manager@gmail.com")
                   .password("123456")
                   .role(Role.MANAGER)
                   .build();
           System.out.println("Manager Token: " + service.register(manager).getAccessToken());
       };
    }
}
