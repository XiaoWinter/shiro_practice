package com.example.shiro.web;


import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class ShiroController {

    @GetMapping("login")
    public ResponseEntity<String> logoinPAG(){
        return ResponseEntity.ok("登陆成功");
    }

    @PostMapping("login")
    @ResponseBody
    @RequiresAuthentication
    public ResponseEntity<String> logoin(){
        return ResponseEntity.ok("登陆成功");
    }

    @GetMapping("resource/{id}")
    @ResponseBody
    public ResponseEntity<String> getResource(@PathVariable Integer id){
        return ResponseEntity.ok("获得资源");
    }
}
