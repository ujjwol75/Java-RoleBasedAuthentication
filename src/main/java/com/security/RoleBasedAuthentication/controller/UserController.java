package com.security.RoleBasedAuthentication.controller;

import com.security.RoleBasedAuthentication.common.UserConstant;
import com.security.RoleBasedAuthentication.entity.User;
import com.security.RoleBasedAuthentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserRepository repository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/join")
    public String joinGroup(@RequestBody User user){
        //default role ROLE_USER set gareko
//        System.out.println("user::: "+ user);
        user.setRoles(UserConstant.DEFAULT_ROLE);
        String encryptedpwd = passwordEncoder.encode(user.getPassword());
        user.setPassword(encryptedpwd);

//        System.out.println("user:::: "+ user);
        repository.save(user);
        return "Hi "+ user.getUsername()+ " welcome to group!";
    }


    //If loggedin user is ADMIN-> He can give two access: ADMIN or MODERATOR
    //If loggedin user is MODERATOR-> He can give onlY one access: MODERATOR
    @GetMapping("access/{userId}/{userRole}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MODERATOR')")
    public String giveAccessToUser(@PathVariable int userId,@PathVariable String userRole, Principal principal){
        User user = repository.findById(userId).get();
        List<String> activeRoles = getRolesByLoggedInUser(principal);
        System.out.println("activeRoles: "+ activeRoles);
        String newRole = "";

        if(activeRoles.contains(userRole)){
            System.out.println("ROLE LAST::");

            newRole = user.getRoles()+","+userRole;
            user.setRoles(newRole);
            System.out.println("ROLE LAST::"+user.getRoles());
        }
        repository.save(user);
        return "Hi "+ user.getUsername()+ " New Role assign to you by "+ principal.getName();

    }


    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> loadUsers(){
        return repository.findAll();
    }

    @GetMapping("/test")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String testUserAccess(){
        return "user can only access this !";
    }


    private List<String> getRolesByLoggedInUser(Principal principal){
        System.out.println("getLoggedInUser:: "+ getLoggedInUser(principal));
        String roles = getLoggedInUser(principal).getRoles();
        System.out.println("roles:: "+ roles);
        List<String> assignRoles = Arrays.stream(roles.split(",")).collect(Collectors.toList());
        if(assignRoles.contains("ROLE_ADMIN")){
            System.out.println("userConstant bata aako value:: "+ UserConstant.ADMIN_ACCESS);
            System.out.println("stream garepaxi aauni value:: "+ Arrays.stream(UserConstant.ADMIN_ACCESS).collect(Collectors.toList()));
            return Arrays.stream(UserConstant.ADMIN_ACCESS).collect(Collectors.toList());
        } if(assignRoles.contains("ROLE_MODERATOR")){
            return Arrays.stream(UserConstant.MODERATOR_ACCESS).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    private User getLoggedInUser(Principal principal){
        return repository.findByUsername(principal.getName()).get();
    }

}
