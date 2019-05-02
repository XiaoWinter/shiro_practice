package com.example.shiro.config;

import com.example.shiro.realm.UserRealm;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

@Configuration
public class ShiroConfig {
    /**
     * 创建ShiroFilterFactoryBean
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(){
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        //设置安全管理器
        filterFactoryBean.setSecurityManager(defaultWebSecurityManager());

        /**
         * 添加Shiro内置过滤器
         * 常用：
         *    anon:无需认证（登录）就能访问
         *    authc:必须认证才能访问
         *    user:使用rememberMe功能可以直接访问
         *    perms:该资源必须得到资源权限才能访问
         *    role:该资源必须得到角色权限才能访问
         */
        //权限map
        Map<String, String> filtermap = new LinkedHashMap<>();
        //设置方式filtermap.put(请求URL,内置过滤器);
        //不拦截
        filtermap.put("/login","anno");
        filtermap.put("/index","anno");
        //授权过滤器

        filtermap.put("/resource","perms[user:add]");//需要权限user:add


        //最后添加到map
        filtermap.put("/*","authc");
        //设置登陆跳转页面
        filterFactoryBean.setLoginUrl("/login");
        //授权提示页面
        filterFactoryBean.setUnauthorizedUrl("/noauth");
        //设置权限
        filterFactoryBean.setFilterChainDefinitionMap(filtermap);


        return filterFactoryBean;
    }
    /**
     * 创建DefaultWebSecurityManager
     */
    @Bean
    public DefaultWebSecurityManager defaultWebSecurityManager(){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(userRealm());
        return securityManager;
    }
    /**
     * 创建Realm
     */
    @Bean
    public UserRealm userRealm(){
        return new UserRealm();
    }

}
