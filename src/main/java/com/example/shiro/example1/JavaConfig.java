package com.example.shiro.example1;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.permission.WildcardPermissionResolver;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;

public class JavaConfig {
    public static void main(String[] args) {

        //初始化一个securityManager
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        //初始化一个authenticator
        ModularRealmAuthenticator authenticator = new ModularRealmAuthenticator();
        //设置认证策略，至少一个通过
        authenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        //设置securityManager的认证器
        securityManager.setAuthenticator(authenticator);

        //初始化一个授权器
        ModularRealmAuthorizer authorizer = new ModularRealmAuthorizer();
        //配置通配符解析器
        authorizer.setPermissionResolver(new WildcardPermissionResolver());
        //设置securityManager的授权器
        securityManager.setAuthorizer(authorizer);

        //设置Raml数据源
        securityManager.setRealm(new MyRealm());

        //将securityManager加到上下文
        SecurityUtils.setSecurityManager(securityManager);

        //执行认证
        //获得主体
        Subject subject = SecurityUtils.getSubject();
        
        //设置token
        UsernamePasswordToken user = new UsernamePasswordToken("user", "123456");

        //登陆
        try {
            subject.login(user);
            System.out.println("登陆成功");
        }catch (UnknownAccountException uae){
            System.out.println("用户名错误");
        }catch (IncorrectCredentialsException ice){
            System.out.println("密码错误");
        }


    }
    static class MyRealm implements Realm{

        @Override
        public String getName() {
            return "myRealm";
        }

        @Override
        public boolean supports(AuthenticationToken authenticationToken) {
            return authenticationToken instanceof UsernamePasswordToken;
        }

        @Override
        public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
            String principal = (String) authenticationToken.getPrincipal();
            String credentials = new String((char[])authenticationToken.getCredentials());

            if (!principal.equals("user"))
                throw new UnknownAccountException();
            if (!credentials.equals("123456"))
                throw new IncorrectCredentialsException();

            return new SimpleAuthenticationInfo(principal,credentials,getName());
        }
    }
}
