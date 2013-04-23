package io.ifar.security.realm;

import com.google.common.base.Strings;
import io.ifar.security.dao.IdentifiedUserSecurityDAO;
import io.ifar.security.dao.UserSecurityDAO;
import io.ifar.security.dao.jdbi.DefaultJdbiUserSecurityDAO;
import io.ifar.security.realm.model.ISecurityRole;
import io.ifar.security.realm.model.ISecurityUser;
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

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;

/**
 * A Shiro security realm with ISecurityUser (Subject) data provided by a DAO implemented via JDBI.
 */
public class JdbiShiroRealm extends AuthorizingRealm {

    private static final Logger LOG = LoggerFactory.getLogger(JdbiShiroRealm.class);

    /**
     * Which fields from the DefaultUserImpl instance to provide as Principal identifiers to Shiro.
     */
    public static enum PrincipalValueField {
        USER_ID, USERNAME
    }

    protected UserSecurityDAO userSecurityDAO = null;
    protected List<PrincipalValueField> principalValueFields = Arrays.asList(PrincipalValueField.USER_ID);
    protected boolean didAuthentication = false;
    protected boolean passwordRequired = true;
    protected boolean daoFromDbi = false;

    /**
     * Creates a new instance with no UserDAO. Calls {@link #JdbiShiroRealm(io.ifar.security.dao.UserSecurityDAO)}
     * passing in null.
     * <p/>
     * <p>UserDAO would need to be set via {@link #setUserSecurityDAO(io.ifar.security.dao.UserSecurityDAO)}
     * before using the instance. </p>
     */
    public JdbiShiroRealm() {
        this((UserSecurityDAO) null);
    }

    /**
     * Create a JdbiShiroRealm using the provided DBI instance.  An onDemand UserDAO will be created
     * based on the {@link DefaultJdbiUserSecurityDAO} class and used to call {@link #JdbiShiroRealm(io.ifar.security.dao.UserSecurityDAO)}.
     *
     * @param dbi DBI instance to use to create a UserDAO.
     */
    public JdbiShiroRealm(DBI dbi) {
        this(dbi.onDemand(DefaultJdbiUserSecurityDAO.class));
        daoFromDbi = true;
    }

    /**
     * Creates an instance with the specified {@code UserSecurityDAO}.
     * Calls {@link #JdbiShiroRealm(org.apache.shiro.authc.credential.CredentialsMatcher, io.ifar.security.dao.UserSecurityDAO)}
     * passing in a new {@link PasswordMatcher} with its default settings, and {@code userSecurityDAO}.
     *
     * @param userSecurityDAO a {@link UserSecurityDAO} used to retrieve user credentials and role/permission data.
     */
    public JdbiShiroRealm(UserSecurityDAO userSecurityDAO) {
        this(new PasswordMatcher(), userSecurityDAO);       // Default config.  Should work out of the box.
    }

    /**
     * Creates an instance with the specified {@link CredentialsMatcher} and {@link UserSecurityDAO}.
     * Calls {@link AuthorizingRealm#AuthorizingRealm(org.apache.shiro.authc.credential.CredentialsMatcher)}
     * passing in {@code matcher}.  If {@code userSecurityDAO} is not null, it is set via {@link #setUserSecurityDAO(io.ifar.security.dao.UserSecurityDAO)}}.
     *
     * @param matcher         the {@link CredentialsMatcher} to use for authenticating users.
     * @param userSecurityDAO the {@link UserSecurityDAO} to use for looking up {@link io.ifar.security.dao.jdbi.DefaultUserImpl}s.
     */
    public JdbiShiroRealm(CredentialsMatcher matcher, UserSecurityDAO userSecurityDAO) {
        super(matcher);
        this.userSecurityDAO = userSecurityDAO;
    }

    synchronized public List<PrincipalValueField> getPrincipalValueFields() {
        return principalValueFields;
    }

    synchronized public void setPrincipalValueFields(List<PrincipalValueField> principalValueFields) {
        checkArgument(principalValueFields != null && principalValueFields.size() > 0,
                "principalValueFields argument must contain at least one value");
        assert (principalValueFields != null);
        for (PrincipalValueField pv : this.principalValueFields) {
            if (didAuthentication) {
                if (!principalValueFields.contains(pv)) {
                    LOG.warn("PrincipalValueField '{}' may have been used for a prior authentication and will henceforth no longer be used for retrieving authorization data.", pv);
                }
            }
        }

        this.principalValueFields = principalValueFields;
    }

    public void setDbi(DBI dbi) {
        this.userSecurityDAO = (dbi == null) ? null : dbi.onDemand(DefaultJdbiUserSecurityDAO.class);
        daoFromDbi = true;
    }

    public void close(DBI dbi) {
        if (dbi != null && userSecurityDAO != null && daoFromDbi) {
            dbi.close(userSecurityDAO);
            this.userSecurityDAO = null;
            daoFromDbi = false;
        }
    }

    public void setUserSecurityDAO(UserSecurityDAO UserSecurityDAO) {
        this.userSecurityDAO = UserSecurityDAO;
        daoFromDbi = false;
    }

    public UserSecurityDAO getUserSecurityDAO() {
        return userSecurityDAO;
    }

    /**
     * Whether or not a password must be provided when performing Authentication.
     *
     * @return default value is {@code true}.
     */
    public boolean isPasswordRequired() {
        return passwordRequired;
    }

    public void setPasswordRequired(boolean passwordRequired) {
        this.passwordRequired = passwordRequired;
    }

    public void afterPropertiesSet() {
        checkState(UsernamePasswordToken.class.isAssignableFrom(getAuthenticationTokenClass()),
                "This JdbiShiroRealm is coded to work with UsernamePasswordToken instances.");
        if (userSecurityDAO == null) {
            throw new IllegalStateException("Configuration error: To function as a Realm instance, userSecurityDAO must not be null.");
        }
        if (principalValueFields == null || principalValueFields.size() < 1) {
            throw new IllegalStateException("To function as a Realm instance, principalValueFields must not be null or empty.");
        } else {
            PrincipalValueField firstPVF = principalValueFields.get(0);
            if (PrincipalValueField.USER_ID.equals(firstPVF) && (userSecurityDAO instanceof IdentifiedUserSecurityDAO)) {
                throw new IllegalStateException("UserSecurityDAO must be an instance of the IdentifiedUserSecurityDAO sub-type for this configuration. The first PrincipalValueField is USER_ID, so the DAO needs to expose the getUserRoles((Long) principalId) method to support this usage, or the principalValueFields need to be changed to make USERNAME the primary principalId.");
            }
        }
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authNToken) throws AuthenticationException {
        checkArgument(UsernamePasswordToken.class.isAssignableFrom(authNToken.getClass()),
                "doGetAuthenticationInfo(): AuthenticationToken argument needs to be an instance of UsernamePasswordToken. Was an instance of '%s' instead.",
                authNToken.getClass().getName());
        UsernamePasswordToken upToken = (UsernamePasswordToken) authNToken;

        String username = upToken.getUsername();
        if (Strings.isNullOrEmpty(username)) {
            LOG.error("doGetAuthenticationInfo() requires a non-null, non-empty username");
            throw new AccountException("username is required by this realm.");
        }

        ISecurityUser user;
        try {
            // No need to fetch the Roles at this point.
            user = getUserSecurityDAO().findUserWithoutRoles(username);
        } catch (RuntimeException ex) {
            LOG.error("Error retrieving user '{}' from database. {}", username, ex.getMessage());
            if (ex instanceof AuthenticationException) {
                throw ex;
            } else {
                throw new AuthenticationException("Error retrieving user '" + username + "'.", ex);
            }
        }
        if (user != null) {
            if (!username.equals(user.getUsername())) {
                LOG.error("Database is inconsistent.  Queried for user with username of '{}', retrieved username of '{}'.",
                        username, user.getUsername());
                throw new AccountException("database error: username mis-match");
            }
            String password = user.getPassword();
            if (isPasswordRequired() && password == null) {
                LOG.warn("Password is required and username '{}' has a null password. Treating account as disabled.", username);
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

        LOG.debug("Retrieving Roles & Permissions for Subject (aka, DefaultUserImpl) identified by '{}'.", principalId);

        Set<ISecurityRole> roles;
        try {
            if (principalId instanceof Long) {
                LOG.debug("Current principalId is of type Long, treating as a DefaultUserImpl.id value.");
                UserSecurityDAO usd = getUserSecurityDAO();
                if (usd instanceof IdentifiedUserSecurityDAO) {
                    roles = ((IdentifiedUserSecurityDAO) getUserSecurityDAO()).getUserRoles((Long) principalId);
                } else {
                    throw new IllegalStateException("UserSecurityDAO must be an instance of the IdentifiedUserSecurityDAO sub-type for this operation. PrincipalCollection's available principal is of type Long, the DAO needs to expose the getUserRoles((Long) principalId) method to support this usage, or change the principalValueFields to make USERNAME the primary principalId.");
                }
            } else if (principalId instanceof String) {
                LOG.debug("Current principalId is of type Long, treating as a DefaultUserImpl.username value.");
                roles = getUserSecurityDAO().getUserRoles((String) principalId);
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
            for (ISecurityRole role : roles) {
                LOG.debug("DefaultUserImpl: '{}', adding DefaultRoleImpl '{}'.", principalId, role);
                info.addRole(role.getName());
                info.addStringPermissions(role.getPermissions());
            }
            return info;
        } else {
            return null;
        }
    }

}
