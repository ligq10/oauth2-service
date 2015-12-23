package com.changhongit.loving;

import com.changhongit.loving.oauth2.TokenAuthFilter;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.boot.orm.jpa.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.servlet.DispatcherType;
import java.util.EnumSet;

@Configuration
@EntityScan(basePackages = "com.changhongit.loving.entity")
@ComponentScan(basePackages = "com.changhongit.loving")
@EnableAutoConfiguration
public class Application {

    private static final int DEFAULT_MAX_TOTAL_CONNECTIONS = 1000;

    private static final int DEFAULT_MAX_CONNECTIONS_PER_ROUTE = 100;

	public static void main(String[] args) {

		SpringApplication.run(Application.class, args);

	}

    @Bean
    @DependsOn("tokenAuthFilter")
    public FilterRegistrationBean tokenAuthFilterRegisterBean(){
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
        filterRegistrationBean.setFilter(tokenAuthFilter());
        filterRegistrationBean.setEnabled(false);
        filterRegistrationBean.setDispatcherTypes(EnumSet.allOf(DispatcherType.class));
        return filterRegistrationBean;
    }

    @Bean
    TokenAuthFilter tokenAuthFilter(){
        return new TokenAuthFilter();
    }

    @Bean
    RestTemplate restTemplate(){

        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(DEFAULT_MAX_TOTAL_CONNECTIONS);
        connectionManager.setDefaultMaxPerRoute(DEFAULT_MAX_CONNECTIONS_PER_ROUTE);
        HttpClientBuilder httpClient = HttpClientBuilder.create().setConnectionManager(connectionManager);

        HttpComponentsClientHttpRequestFactory httpRequestFactory = new HttpComponentsClientHttpRequestFactory(httpClient.build());

        return new RestTemplate(httpRequestFactory);
    }

}
