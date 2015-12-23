package com.changhongit.loving.controllers;

import com.changhongit.loving.model.AccessCode;
import com.changhongit.loving.model.GetAccessTokenRequest;
import com.changhongit.loving.repository.OauthClientsDetailsRepository;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController()
public class OauthController {

    Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private Environment env;

    @Autowired
    private OauthClientsDetailsRepository clientsDetailsRepository;


    @Autowired
    private RestTemplate restTemplate;

	@RequestMapping(value = "oauth/code", produces = MediaType.APPLICATION_JSON_VALUE)
         public ResponseEntity<Object> getAccessCode(HttpServletRequest request,
                                                      HttpServletResponse response, @RequestBody String requestBody,
                                                      @RequestParam String code) throws Exception {

        Map<String, Object> responseJson = new HashMap<String, Object>();
        responseJson.put("code", code);

        return new ResponseEntity<Object>(responseJson, HttpStatus.OK);

    }

    @RequestMapping(value = "oauth/accesstoken", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public HttpEntity<?> getAccessToken(@RequestBody GetAccessTokenRequest getAccessTokenRequest) throws Exception {

        try {
            String accessCode = getAccessCode(getAccessTokenRequest.getLoginName(), getAccessTokenRequest.getPassword());
            String accessToken = getAccessToken(accessCode);
            return new ResponseEntity<>(accessToken, HttpStatus.OK);
        } catch (HttpClientErrorException e){
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }catch (Exception e){
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private String getAccessCode(String username, String password) {

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        List<String> auth = new ArrayList<>();

        String plainCreds = username + ":" + password;
        byte[] plainCredsBytes = plainCreds.getBytes();
        byte[] base64CredsBytes = Base64.encodeBase64(plainCredsBytes);
        String base64Creds = new String(base64CredsBytes);

        auth.add("Basic " + base64Creds);
        headers.put("Authorization", auth);

        ResponseEntity<AccessCode> exchange = restTemplate.exchange(
                String.format(env.getRequiredProperty("code.endpoint")),
                HttpMethod.GET, new HttpEntity<>("", headers),
                AccessCode.class);
        return exchange.getBody().getCode();
    }

    private String getAccessToken(String code) {

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        List<String> auth = new ArrayList<>();
        auth.add(env.getRequiredProperty("quickAccessToken.auth"));
        headers.put("Authorization", auth);

        ResponseEntity<String> exchange = restTemplate.exchange(
                String.format(env.getRequiredProperty("token.endpoint"), code),
                HttpMethod.POST, new HttpEntity<>("", headers),
                String.class);
        return exchange.getBody();
    }


}
