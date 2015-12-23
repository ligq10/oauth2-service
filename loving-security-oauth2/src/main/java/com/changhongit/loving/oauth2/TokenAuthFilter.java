package com.changhongit.loving.oauth2;

import com.changhongit.loving.model.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class TokenAuthFilter extends GenericFilterBean {

    @Autowired
    private Environment env;

    private static final String SECURITY_TOKEN_HEADER = "X-Token";

    private RestTemplate restTemplate = new RestTemplate();

    Logger logger = LoggerFactory.getLogger(getClass());


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse servletResponse = (HttpServletResponse) response;
        String requestURI = httpServletRequest.getRequestURI();
        if(requestURI.startsWith("/security/users") || requestURI.startsWith("/security/apps") || requestURI.startsWith("/security/roles") || requestURI.equals("/security/")){

            String token = httpServletRequest.getHeader(SECURITY_TOKEN_HEADER);
            if (StringUtils.isEmpty(token)) {
                servletResponse.sendError(401, "No access token found in http header 'X-Token'");
                return;
            }
            try {
                authUserByToken(token);
            } catch (HttpClientErrorException clientError) {
                servletResponse.sendError(403, "Your access token is invalid or expired.");
                logger.warn("Warning: ", clientError);
                return;
            } catch (Exception e) {
                servletResponse.sendError(500, "Server error during validating your access token");
                logger.error("Error: ", e);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }

    private void authUserByToken(String tokenRaw) throws Exception {

        AccessToken accessToken = restTemplate.getForObject(String.format(env.getProperty("checkToken.endpoint"), tokenRaw), AccessToken.class);
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (String authority : accessToken.getAuthorities()) {
            authorities.add(new SimpleGrantedAuthority(authority));
        }
        AbstractAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(accessToken.getUserName(), "", authorities);
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
