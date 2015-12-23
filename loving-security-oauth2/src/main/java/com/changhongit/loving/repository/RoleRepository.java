package com.changhongit.loving.repository;

import com.changhongit.loving.entity.Role;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;
import org.springframework.security.access.prepost.PreAuthorize;

@RepositoryRestResource(path = "roles", collectionResourceRel = "roles")
public interface RoleRepository extends CrudRepository<Role, String>{

    @RestResource(exported = false)
    Role findByName(String name);

    @Override
    Role save(Role entity);

    @Override
    Role findOne(String s);

    @Override
    Iterable<Role> findAll();

    @Override
    @PreAuthorize("hasAuthority('USER_MANAGER')")
    void delete(String s);

    @Override
    @PreAuthorize("hasAuthority('USER_MANAGER')")
    void delete(Role entity);
}
