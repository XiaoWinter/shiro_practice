package com.example.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * 自定义的UserRealm继承AuthorizingRealm实现认证和授权，可以结合数据库
 */
public class UserRealm extends AuthorizingRealm {
    /**
     * 授权
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("授权");
        /**数据库方式
         User user = (User)SecurityUtils.getSubject();//认证时存的principal
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addStringPermissions(user.getPermission());//

        return info;*/

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //添加权限
        info.addStringPermission("perms[user:add]");

        return info;
    }

    /**
     *  认证
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("认证");
        
        /**数据库方式
        UsernamePasswordToken utoken = (UsernamePasswordToken) token;
        User user = userMapper.getByName(utoken.getUsername());
        if(user == null)
            return null;
        return new SimpleAuthenticationInfo(user,user.getPassword(),getName());*/

        //数据库获取username，password
        String username ="";
        String password = "";

        //获取用户名
        UsernamePasswordToken utoken = (UsernamePasswordToken) token;
        if (!utoken.getUsername().equals(username))
            return null;
        /** principal 主体唯一
        1）可以是uuid
        2）数据库中的主键
        3）LDAP UUID或静态DN
        4）在所有用户帐户中唯一的字符串用户名。

        也就是说这个值必须是唯一的。也可以是邮箱、身份证等值。*/
        return new SimpleAuthenticationInfo(username,password,getName());
    }
}
