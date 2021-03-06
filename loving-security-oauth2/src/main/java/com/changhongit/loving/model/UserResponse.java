package com.changhongit.loving.model;

import org.springframework.hateoas.ResourceSupport;

public class UserResponse extends ResourceSupport{

    private String uuid;
    private String name;

    public UserResponse(String uuid, String name) {
        this.uuid = uuid;
        this.name = name;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
