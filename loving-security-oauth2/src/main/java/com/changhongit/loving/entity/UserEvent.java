package com.changhongit.loving.entity;

import kafka.javaapi.producer.Producer;
import kafka.producer.KeyedMessage;
import kafka.producer.ProducerConfig;
import net.minidev.json.JSONValue;

import com.changhongit.loving.config.KafkaProducerConfiguration;

public class UserEvent {
	
	public static void UserRegisteredEvent(User user,KafkaProducerConfiguration kafkaProducerConfiguration){
    	PushEntity entity = new PushEntity();
    	entity.setEnabled(user.getEnabled());
    	entity.setLoginName(user.getLoginName());
    	entity.setPassword(user.getPassword());
    	entity.setUuid(user.getId().toString());
    	String userjson = JSONValue.toJSONString(entity);
		Producer<String, String> producer  = null;
		try {
			producer = new Producer<String, String>(new ProducerConfig(kafkaProducerConfiguration.getProperties()));
			producer.send(new KeyedMessage<String, String>(KafkaProducerConfiguration.TOPIC,userjson));
		} catch (Exception e) {
			e.printStackTrace();
		}finally{
			if(producer!=null){
				producer.close();
			}
		}
	}
}
