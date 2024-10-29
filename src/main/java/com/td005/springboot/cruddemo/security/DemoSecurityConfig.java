package com.td005.springboot.cruddemo.security;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class DemoSecurityConfig {

    //add support for JDBC.... no more hardcoded users
    @Bean
    public UserDetailsManager detailsManager(DataSource dataSource)
    {
        //Özel tabloları kullanarak kullanıcıyı almak ve ayrıca rolleri almak için sorgu sağladık
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        //define query to retrieve a user by username
        //Bir kullanıcıyı kullanıcı adına göre almak için sorguyu tanımla
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id,pw,active from members where user_id=?");

        //define query to retrieve the authorities/roles by username
        //Yetkileri/rolleri kullanıcı adına göre almak için sorguyu tanımlayın
        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                "select user_id,role from roles where user_id=?");
        return jdbcUserDetailsManager;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(configurer->
                configurer
                        .requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.GET,"api/employees/**").hasRole("EMPLOYEE")
                        .requestMatchers(HttpMethod.POST,"/api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.PUT,"api/employees").hasRole("MANAGER")
                        .requestMatchers(HttpMethod.DELETE,"api/employees/**").hasRole("ADMIN")
        );

        //HTTP temel kimlik doğrulamasını kullan
        http.httpBasic(Customizer.withDefaults());
        //Siteler Arası İstek sahteciliği (CSRF) devre dışı bırakıldı
        //genel olarak POST , PUT , DELETE ve/veya PATCH kullanan durum bilgisi olmayan REST API'leri için gerekli değildir
        http.csrf(csrf->csrf.disable());
        return http.build();
    }




    /*
    @Bean
    public InMemoryUserDetailsManager userDetailsManager()
    {

        UserDetails john = User.builder()
                .username("john")
                .password("{noop}test123")
                .roles("EMPLOYEE")
                .build();


        UserDetails marry = User.builder()
                .username("marry")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER")
                .build();

        UserDetails susan = User.builder()
                .username("susan")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();




        return new InMemoryUserDetailsManager(john,marry,susan);

    }
*/
}
