#Apache_Shiro Use

### Demo1
####ini配置文件的方式使用shiro
* 定义配置文件

```
# =============================================================================
# Tutorial INI configuration
#
# Usernames/passwords are based on the classic Mel Brooks' film "Spaceballs" :)
# =============================================================================

# -----------------------------------------------------------------------------
# Users and their (optional) assigned roles
# username = password, role1, role2, ..., roleN
# -----------------------------------------------------------------------------
[users]
root = secret, admin
guest = guest, guest
presidentskroob = 12345, president
darkhelmet = ludicrousspeed, darklord, schwartz
lonestarr = vespa, goodguy, schwartz

# -----------------------------------------------------------------------------
# Roles with assigned permissions
# roleName = perm1, perm2, ..., permN
# -----------------------------------------------------------------------------
[roles]
admin = *
schwartz = lightsaber:*
goodguy = winnebago:drive:eagle5
```

        
        
* 使用配置文件创建securityManager并使用shiro基本功能（认证，授权）

```java
package com.example.shiro.example1;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Tutorial {

    private static final transient Logger log = LoggerFactory.getLogger(Tutorial.class);


    public static void main(String[] args) {
        log.info("My First Apache Shiro Application");

        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();
        //绑定到上下文
        SecurityUtils.setSecurityManager(securityManager);


        // 获取当前执行用户:
        Subject currentUser = SecurityUtils.getSubject();

        // 做点跟 Session 相关的事
        Session session = currentUser.getSession();
        session.setAttribute("someKey", "aValue");
        String value = (String) session.getAttribute("someKey");
        if (value.equals("aValue")) {
            log.info("Retrieved the correct value! [" + value + "]");
        }

        // 登录当前用户检验角色和权限
        if (!currentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
            token.setRememberMe(true);
            try {
                currentUser.login(token);
            } catch (UnknownAccountException uae) {
                log.info("There is no user with username of " + token.getPrincipal());
            } catch (IncorrectCredentialsException ice) {
                log.info("Password for account " + token.getPrincipal() + " was incorrect!");
            } catch (LockedAccountException lae) {
                log.info("The account for username " + token.getPrincipal() + " is locked.  " +
                        "Please contact your administrator to unlock it.");
            }
            // ... 捕获更多异常
            catch (AuthenticationException ae) {
                //无定义?错误?
            }
        }

        //说出他们是谁:
        //打印主要识别信息 (本例是 username):
        log.info("User [" + currentUser.getPrincipal() + "] logged in successfully.");

        //测试角色:
        if (currentUser.hasRole("schwartz")) {
            log.info("May the Schwartz be with you!");
        } else {
            log.info("Hello, mere mortal.");
        }

        //测试一个权限 (非（instance-level）实例级别)
        if (currentUser.isPermitted("lightsaber:weild")) {
            log.info("You may use a lightsaber ring.  Use it wisely.");
        } else {
            log.info("Sorry, lightsaber rings are for schwartz masters only.");
        }

        //一个(非常强大)的实例级别的权限:
        if (currentUser.isPermitted("winnebago:drive:eagle5")) {
            log.info("You are permitted to 'drive' the winnebago with license plate (id) 'eagle5'.  " +
                    "Here are the keys - have fun!");
        } else {
            log.info("Sorry, you aren't allowed to drive the 'eagle5' winnebago!");
        }

        //完成 - 退出t!
        currentUser.logout();

        System.exit(0);
    }
}


```

### Demo2
#### java编码的方式配置securityManager使用shiro
```java
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
    //自定义Realm
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
```
