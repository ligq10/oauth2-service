package com.changhongit.loving.config;


import java.util.Properties;

import kafka.javaapi.producer.Producer;
import kafka.producer.ProducerConfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;

@Configuration
@PropertySource(value = { "classpath:application.properties" })
public class KafkaProducerConfiguration {
	public final static String TOPIC = "USER-INFO";
    @Autowired
	private Environment environment;
    @Bean
    public Properties getProperties(){
        Properties props = new Properties();
        props.put("metadata.broker.list", environment.getProperty("metadata.broker.list"));
        props.put("serializer.class", "kafka.serializer.StringEncoder");
        props.put("key.serializer.class", "kafka.serializer.StringEncoder");
        props.put("request.required.acks",environment.getProperty("request.required.acks"));
        return props;
    }
}