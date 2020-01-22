package com.security.composite.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableOAuth2Client
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // Section I:
    // basic form-based security
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        //Authorization
        http.authorizeRequests().antMatchers("/", "/signup", "/login", "/logout").permitAll();
        http.authorizeRequests().antMatchers("/userInfo").access("hasAnyRole('USER', 'ADMIN')");
        http.authorizeRequests().antMatchers("/admin").access("hasRole('ADMIN')");

        //access denied page
        http.authorizeRequests().and().exceptionHandling().accessDeniedPage("/accessdeny");

        //Login
        http.authorizeRequests().and().formLogin()
                .loginProcessingUrl("/security_login")  //login submission url
                .loginPage("/login")  //load login page
                .defaultSuccessUrl("/userInfo")  //if login success
                .failureUrl("/login?error=true") //if login fail
                .usernameParameter("email")  //login form user email when submission
                .passwordParameter("password"); //login form user password when submission

        //Logout
        http.authorizeRequests().and().logout().logoutUrl("/logout").logoutSuccessUrl("/login");

        //Oauth2
        http.authorizeRequests().and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

        //Remember Me
        http.authorizeRequests().and()
                .rememberMe()
                .rememberMeParameter("remember-me")  //cookie entry name
                .tokenRepository(persistentTokenRepository())
                .tokenValiditySeconds(120000);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }



    // Section II:
    // oauth2 security
    @Autowired
    @Qualifier("oauth2ClientContext")
    OAuth2ClientContext oauth2ClientContext;


    private Filter ssoFilter(){
        CompositeFilter compositeFilter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();

        String googleLinkUrl = "/login/google";
        OAuth2ClientAuthenticationProcessingFilter googleFilter = new OAuth2ClientAuthenticationProcessingFilter(googleLinkUrl);
        OAuth2RestTemplate googleTemplate = new OAuth2RestTemplate(googleAuthCode(), oauth2ClientContext);
        googleFilter.setRestTemplate(googleTemplate);
        UserInfoTokenServices googleTokenServices = new UserInfoTokenServices(googleResource().getUserInfoUri(), googleAuthCode().getClientId());
        googleTokenServices.setRestTemplate(googleTemplate);
        googleFilter.setTokenServices(googleTokenServices);
        filters.add(googleFilter);

        String githubLinkUrl = "/login/github";
        OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter(githubLinkUrl);
        OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(githubAuthCode(), oauth2ClientContext);
        githubFilter.setRestTemplate(githubTemplate);
        UserInfoTokenServices githubTokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), githubAuthCode().getClientId());
        githubTokenServices.setRestTemplate(githubTemplate);
        githubFilter.setTokenServices(githubTokenServices);
        filters.add(githubFilter);

        compositeFilter.setFilters(filters);
        return compositeFilter;
    }


    @Bean
    @ConfigurationProperties("google.client")
    public AuthorizationCodeResourceDetails googleAuthCode(){
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("google.resource")
    public ResourceServerProperties googleResource(){
        return new ResourceServerProperties();
    }

    @Bean
    @ConfigurationProperties("github.client")
    public AuthorizationCodeResourceDetails githubAuthCode(){
        return new AuthorizationCodeResourceDetails();
    }

    @Bean
    @ConfigurationProperties("github.resource")
    public ResourceServerProperties githubResource(){
        return new ResourceServerProperties();
    }

    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oAuth2ClientFilterRegistration(OAuth2ClientContextFilter filter){
        FilterRegistrationBean<OAuth2ClientContextFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.setOrder(-100);
        return registrationBean;
    }



    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        /*JdbcTokenRepositoryImpl tokenRepositoryImpl = new JdbcTokenRepositoryImpl();
        return tokenRepositoryImpl;*/
        InMemoryTokenRepositoryImpl inMemoryTokenRepository = new InMemoryTokenRepositoryImpl();
        return inMemoryTokenRepository;
    }


}
