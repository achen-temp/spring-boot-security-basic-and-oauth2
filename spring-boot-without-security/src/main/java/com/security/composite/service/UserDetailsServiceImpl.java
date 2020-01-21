package com.security.composite.service;

import com.security.composite.enitty.User;
import com.security.composite.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl{

    @Autowired
    UserRepository userRepository;

    //register new user
    public void saveUser(User u){
        //u.setPassword(passwordEncoder.encode(u.getPassword()));
        userRepository.saveUser(u);
    }

    public boolean validateUserPlain(User user) {
        return userRepository.validateUserPlain(user);
    }
}
