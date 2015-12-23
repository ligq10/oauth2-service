package com.changhongit.loving.repository;

import com.changhongit.loving.entity.User;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.data.rest.core.annotation.RestResource;

@RepositoryRestResource(path = "users", collectionResourceRel = "users")
public interface UserRepository extends PagingAndSortingRepository<User, String> {


    @RestResource(exported = false)
    User findByLoginName(String loginName);

    @Override
    User save(User entity);

    @Override
    User findOne(String s);

    @Override
    void delete(String s);

    @Override
    void delete(User entity);
}
