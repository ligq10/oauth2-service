package com.changhongit.loving.model;

import java.util.List;

public class UpdateUserRoleRequest {

    private String loginName;

    private List<String> roleNames;

    public String getLoginName() {
        return loginName;
    }

    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public List<String> getRoleNames() {
        return roleNames;
    }

    public void setRoleNames(List<String> roleNames) {
        this.roleNames = roleNames;
    }
}
