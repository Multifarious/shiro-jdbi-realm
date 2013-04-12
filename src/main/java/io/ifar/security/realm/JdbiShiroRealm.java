package io.ifar.security.realm;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

import com.google.common.base.Strings;
import io.ifar.security.dao.jdbi.DefaultJDBIUserDAO;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.skife.jdbi.v2.DBI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.ifar.security.dao.UserDAO;
import io.ifar.security.realm.model.Role;
import io.ifar.security.realm.model.User;

import java.util.*;

/**
 * A Shiro security realm with User (Subject) data provided by a DAO implemented via JDBI.
 *
 * User: eze@ifar.ifario.us
 * Date: 3/26/13
 */
public class JdbiShiroRealm extends AuthorizingRealm {

    private static final Logger LOG = LoggerFactory.getLogger(JdbiShiroRealm.class);

    /**
     * Which fields from the User instance to provide as Principal identifiers to Shiro.
     */
    public static enum PrincipalValueField
    {
        USER_ID, USERNAME
    }

    protected UserDAO userDAO = null;
    protected List<PrincipalValueField> principalValueFields = Arrays.asList(PrincipalValueField.USER_ID);
    protected boolean didAuthentication = false;

    /**
     * Creates a new instance with no UserDAO. Calls {@link #JdbiShiroRealm(io.ifar.security.dao.UserDAO)} passing in null.
     *
     * <p>UserDAO would need to be set via {@link #setUserDAO(io.ifar.security.dao.UserDAO)}
     * before using the instance. </p>
     */
    public JdbiShiroRealm() {
        this((UserDAO)null);
    }

    /**
     * Create a JdbiShiroRealm using the provided DBI instance.  An onDemand UserDAO will be created
     * based on the {@link DefaultJDBIUserDAO} class and used to call {@link #JdbiShiroRealm(io.ifar.security.dao.UserDAO)}.
     * @param dbi  DBI instance to use to create a UserDAO.
     */
    public JdbiShiroRealm(DBI dbi)
    {
         this(dbi.onDemand(DefaultJDBIUserDAO.class));
    }

    /**
     * Creates an instance with the specified {@code UserDAO}.
     * Calls {@link #JdbiShiroRealm(org.apache.shiro.authc.credential.CredentialsMatcher, io.ifar.security.dao.UserDAO)}
     * passing in a new {@link PasswordMatcher} with its default settings, and {@code userDAO}.
     * @param userDAO a {@link UserDAO} used to retrieve user credentials and role/permission data.
     */
    public JdbiShiroRealm(UserDAO userDAO) {
        this(new PasswordMatcher(), userDAO);       // Default config.  Should work out of the box.
     }

    /**
     * Creates an instance with the specified {@link CredentialsMatcher} and {@link UserDAO}.
     * Calls {@link AuthorizingRealm#AuthorizingRealm(org.apache.shiro.authc.credential.CredentialsMatcher)}
     * passing in {@code matcher}.  If {@code userDAO} is not null, it is set via {@link #setUserDAO(io.ifar.security.dao.UserDAO)}.
     * @param matcher the {@link CredentialsMatcher} to use for authenticating users.
     * @param userDAO the {@link UserDAO} to use for looking up {@link User}s.
     */
    public JdbiShiroRealm(CredentialsMatcher matcher, UserDAO userDAO)
    {
        super(matcher);
        if (userDAO != null) setUserDAO(userDAO);
    }

    synchronized public List<PrincipalValueField> getPrincipalValueFields() {
        return principalValueFields;
    }

    synchronized public void setPrincipalValueFields(List<PrincipalValueField> principalValueFields) {
        checkArgument(principalValueFields != null && principalValueFields.size() > 0,
                "principalValueFields argument must contain at least one value");
        for (PrincipalValueField pv : this.principalValueFields) {
            if (didAuthentication) {
                if (!principalValueFields.contains(pv)) {
                    LOG.warn("PrincipalValueField '{}' may have been used for a prior authentication and will henceforth no longer be used for retrieving authorization data.", pv);
                }
            }
        }

        this.principalValueFields = principalValueFields;
    }

    public void setDbi(DBI dbi)
    {
        setUserDAO((dbi == null) ? null : dbi.onDemand(DefaultJDBIUserDAO.class));
    }

    public void setUserDAO(UserDAO userDAO) {
        this.userDAO = userDAO;
    }

    public UserDAO getUserDAO() {
        return userDAO;
    }

    public void afterPropertiesSet() {
        checkState(UsernamePasswordToken.class.isAssignableFrom(getAuthenticationTokenClass()),
                "This JdbiShiroRealm is coded to work with UsernamePasswordToken instances.");
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authNToken) throws AuthenticationException {
        checkArgument(UsernamePasswordToken.class.isAssignableFrom(authNToken.getClass()),
                "doGetAuthenticationInfo(): AuthenticationToken argument needs to be an instance of UsernamePasswordToken. Was an instance of '%s' instead.",
                authNToken.getClass().getName());
        UsernamePasswordToken upToken = (UsernamePasswordToken) authNToken;

        String username = upToken.getUsername();
        if (Strings.isNullOrEmpty(username)) {
            throw new AccountException("username is required by this realm.");
        }

        User user;
        try {
            // No need to fetch the Roles at this point.
            user = userDAO.findUser(username, false);
        } catch (RuntimeException ex) {
            LOG.error("Error retrieving user '" + username + "' from database.", ex);
            throw new UnknownAccountException("No account found for user '" + username + "'.", ex);
        }
        if (user != null) {
            if (!username.equals(user.getUsername())) {
                LOG.error("Database is inconsistent.  Queried for user with username of '{}', retrieved username of '{}'.",
                        username, user.getUsername());
                throw new AccountException("database error: username mis-match");
            }
            String password = user.getPassword();
            if (password == null) {
                LOG.error("Database is inconsistent. Username '{}' has a null password.", username);
                throw new DisabledAccountException("No valid account found for user '" + username + "'.");
            }
            // About to use the PrincipalValues, set a flag.
            didAuthentication = true;
            List<PrincipalValueField> pvs = getPrincipalValueFields();
            Set<Object> principalVals = new LinkedHashSet<>(pvs.size());
            for (PrincipalValueField pv : pvs) {
                if (PrincipalValueField.USER_ID.equals(pv)) {
                    principalVals.add(user.getId());
                } else if (PrincipalValueField.USERNAME.equals(pv)) {
                    principalVals.add(user.getUsername());
                }
            }
            SimplePrincipalCollection spc = new SimplePrincipalCollection(principalVals, getName());
            return new SimpleAuthenticationInfo(spc, password);
        } else {
            return null;
        }
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        if (principals == null) {
            throw new AuthorizationException("PrincipalCollection argument (principals) cannot be null.");
        }
        Object principalId = getAvailablePrincipal(principals);
        if (principalId == null) {
            throw new AuthorizationException("no principal available; no one to authorize.");
        }

        LOG.debug("Retrieving Roles & Permissions for Subject (aka, User) identified by '{}'.", principalId);

        Set<Role> roles;
        try {
            if (principalId instanceof Long) {
                LOG.debug("Current principalId is of type Long, treating as a User.id value.");
                roles = userDAO.getUserRoles((Long)principalId);
            } else if (principalId instanceof String) {
                LOG.debug("Current principalId is of type Long, treating as a User.username value.");
                roles = userDAO.getUserRoles((String)principalId);
            } else {
                LOG.error("The provided principal is of an unsupported type. This method supports Long and String typed identifiers.  Provided type was {}; provided value was: {}.", principalId.getClass().getName(), principalId);
                throw new AuthorizationException("The provided principal is of an unsupported type. This method supports Long and String typed identifiers.  Provided type was " + principalId.getClass().getName() + "; provided value was: " + principalId);
            }
        } catch (RuntimeException ex) {
            LOG.error("Error retrieving Roles from database for user with identifier '" + principalId + "'.", ex);
            throw new AuthorizationException("No account found for user identified by '" + principalId + "'.", ex);
        }
        if (roles != null && roles.size() > 0) {
            SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
            for (Role role : roles) {
                LOG.debug("User: '{}', adding Role '{}'.", principalId, role);
                info.addRole(role.getName());
                info.addStringPermissions(role.getPermissions());
            }
            return info;
        } else {
            return null;
        }
    }

}
