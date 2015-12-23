package com.changhongit.loving.oauth2;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RedirectLogoutHandler implements LogoutSuccessHandler{

    Logger logger = LoggerFactory.getLogger(getClass());

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        logger.info(request.getRequestURL().toString());
        String redirect_url = request.getParameter("redirect_url");
        if (!StringUtils.isEmpty(redirect_url)){
            try {
                response.sendRedirect(redirect_url);
            } catch (IOException e) {
                logger.error("Error: ", e);
            }
        }
    }
}
