package com.changhongit.loving.eventListener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.core.annotation.HandleBeforeDelete;
import org.springframework.data.rest.core.annotation.RepositoryEventHandler;
import org.springframework.stereotype.Component;

import com.changhongit.loving.entity.User;
import com.changhongit.loving.repository.UserRepository;

@RepositoryEventHandler(User.class)
@Component
public class UserEventListener {
	
	@Autowired
	private UserRepository userRepository;
	
	@HandleBeforeDelete
	public void onBeforeDelete(User user) {
		user.getRoles().clear();
		
	}
}
