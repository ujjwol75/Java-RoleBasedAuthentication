package com.security.RoleBasedAuthentication.service;

import com.security.RoleBasedAuthentication.entity.User;
import com.security.RoleBasedAuthentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// Yo purai clas le k garxa???
// => so we created our own UserDetailsService that is (GroupDetailsService) where we authenticate user based on the
// username . So while login I need to provide username and password. Based on the username, I load the user from
// the database.Then I convert that user object into UserDetails object and return it(because so that it will set it to
// spring security context)...
@Service
public class GroupUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = repository.findByUsername(username);
        // we need to return userDetails object so that we map user into userDetails object...
        return user.map(GroupUserDetails::new).orElseThrow(()-> new UsernameNotFoundException(username+ " does not exist..."));
    }
}
