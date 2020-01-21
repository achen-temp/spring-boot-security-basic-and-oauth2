package com.security.composite.controller;

import com.security.composite.enitty.User;
import com.security.composite.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;

@Controller
public class MainController {

    @Autowired
    UserDetailsServiceImpl service;

    @GetMapping({"/", "/welcome"})
    public String welcomePage(Model model){
        model.addAttribute("message", "This is welcome page!");
        return "welcome";
    }

    @GetMapping("/login")
    public String login(){
        return "loginPage";
    }

    @GetMapping("/signup")
    public String loadSignUpPage(Model model){
        model.addAttribute("user", new User());
        return "signupPage";
    }

    @GetMapping("/userInfo")
    public String userInfo(Model model, Principal principal) {
        String userName = principal.getName();
        System.out.println("User Name: " + userName);
        model.addAttribute("userInfo", userName);
        return "userInfoPage";
    }

    @GetMapping("/admin")
    public String adminPage(Model model, Principal principal) {
        String userName = principal.getName();
        System.out.println("User Name: " + userName);
        model.addAttribute("userInfo", userName);
        return "adminPage";
    }

    @GetMapping("/accessdeny")
    public String accessDenied(Model model, Principal principal) {
        if (principal != null) {
            String message = "Hi " + principal.getName()
                    + "<br> You do not have permission to access this page!";
            model.addAttribute("message", message);
        }
        return "403Page";
    }


    @PostMapping("register")
    public String registerUser(@ModelAttribute User user){
        System.out.println(user);
        service.saveUser(user);
        return "loginPage";
    }

}
