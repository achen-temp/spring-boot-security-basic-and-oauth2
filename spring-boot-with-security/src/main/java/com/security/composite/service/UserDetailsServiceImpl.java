package com.security.composite.service;

import com.security.composite.enitty.User;
import com.security.composite.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user = userRepository.getUserByEmail(s);
        UserBuilder builder = null;
        if(user != null) {
            builder = org.springframework.security.core.userdetails.User.withUsername(user.getEmail());
            //builder.username(user.getEmail());
            builder.password(user.getPassword());
            String[] roles = {user.getRole()}; //create a new user role array
            builder.roles(roles);
        }else {
            throw new UsernameNotFoundException("username not found");
        }
        return builder.build();
    }

    //register new user
    public void saveUser(User u){
        u.setPassword(passwordEncoder.encode(u.getPassword()));
        userRepository.saveUser(u);
    }
}
