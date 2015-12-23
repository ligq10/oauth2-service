package com.changhongit.loving.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebMvcSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private TokenAuthFilter tokenAuthFilter;

	@Autowired
	private DataSource dataSource;

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.jdbcAuthentication()
				.dataSource(dataSource)
				.usersByUsernameQuery(
						"select login_name, password, enabled from user where login_name=?")
				.authoritiesByUsernameQuery(
						"select user.login_name, role.name from user inner join user_roles on user.id = user_roles.user_id inner join role on role.id=user_roles.roles_id where login_name=?");
	}

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/oauth/check_token**","/users/userInfo", "/oauth/accesstoken", "oauth/code**", "/users/checkloginname**", "/guanhutong3g/register", "/css/**", "/fonts/**","/image/**","/js/**");
        web.ignoring().antMatchers(HttpMethod.OPTIONS, "/oauth/**");
    }

    @Override
	protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests().anyRequest().authenticated()
		.and().formLogin().loginPage("/login").permitAll().and().httpBasic().and().logout().logoutSuccessHandler(new RedirectLogoutHandler()).permitAll()
        .and().addFilterBefore(tokenAuthFilter, UsernamePasswordAuthenticationFilter.class);
	}

}
