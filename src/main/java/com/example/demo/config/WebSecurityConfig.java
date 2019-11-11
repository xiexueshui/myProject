package com.example.demo.config;

import com.example.demo.bean.DemoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * @author xie
 * @date 2019/11/11 14:19
 */
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public DemoService demoService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        //userService返回一个userDetail实体，其中包括passwrod，与传入的password进行加密对比，
        auth.userDetailsService(demoService).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()

                .and()
                .formLogin().loginPage("/login_p").loginProcessingUrl("/user/login")
                .usernameParameter("username").passwordParameter("password")
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        AuthenticationException e) throws IOException {
                        resp.setContentType("application/json;charset=utf-8");
                        System.out.print(e.toString());

                        resp.setStatus(401);
                        PrintWriter writer = resp.getWriter();
                        writer.write(e.toString());
                        writer.flush();
                        writer.close();
                    }
                })
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req,
                                                        HttpServletResponse resp,
                                                        Authentication auth) throws IOException {
                        resp.setContentType("application/json;charset=utf-8");

                        System.out.print(auth);
                        PrintWriter out = resp.getWriter();
                        out.write("success");
                        out.flush();
                        out.close();
                    }
                })
                .permitAll()
                .and().csrf().disable();

    }
}
