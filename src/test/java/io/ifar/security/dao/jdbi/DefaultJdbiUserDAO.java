package io.ifar.security.dao.jdbi;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import io.ifar.security.realm.model.ISecurityRole;
import org.apache.shiro.authc.AuthenticationException;
import org.skife.jdbi.v2.TransactionIsolationLevel;
import org.skife.jdbi.v2.sqlobject.Bind;
import org.skife.jdbi.v2.sqlobject.SqlQuery;
import org.skife.jdbi.v2.sqlobject.SqlUpdate;
import org.skife.jdbi.v2.sqlobject.Transaction;
import org.skife.jdbi.v2.sqlobject.helpers.MapResultAsBean;
import org.skife.jdbi.v2.sqlobject.mixins.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.ifar.security.dao.UserDAO;

import java.util.*;


/**
 * Implementation of UserDAO via DBI.
 */
public abstract class DefaultJdbiUserDAO implements UserDAO,
        Transactional<DefaultJdbiUserDAO> {

    private final static Logger LOG = LoggerFactory.getLogger(DefaultJdbiUserDAO.class);

    protected final static String EnabledRolesPermissionsBaseSelectPrefix =
            "SELECT roles.role_name AS roleName, roles_permissions.permission AS permission"
                    + " FROM users_roles left join roles on users_roles.role_name = roles.role_name"
                    + " left join roles_permissions on roles.role_name = roles_permissions.role_name"
                    + " WHERE roles.enabled AND ";
    protected final static String RolesPermissionsBaseSelectPrefix =
            "SELECT roles.role_name AS roleName, roles_permissions.permission AS permission"
                    + " FROM users_roles left join roles on users_roles.role_name = roles.role_name"
                    + " left join roles_permissions on roles.role_name = roles_permissions.role_name"
                    + " WHERE ";
    protected final static String EnabledUserRolesPermissionsBaseSelectPrefix =
            "SELECT users.user_Id AS userId, users.username AS username, users.password AS password,"
                    + " roles.role_name AS roleName, roles_permissions.permission AS permission"
                    + " FROM users left join users_roles on users.user_id = users_roles.user_id"
                    + " left join roles on users_roles.role_name = roles.role_name"
                    + " left join roles_permissions on roles.role_name = roles_permissions.role_name"
                    + " WHERE users.enabled AND (roles.enabled OR roles.enabled IS NULL) AND ";
    protected final static String UserRolesPermissionsBaseSelectPrefix =
            "SELECT users.user_Id AS userId, users.username AS username, users.password AS password,"
                    + " roles.role_name AS roleName, roles_permissions.permission AS permission"
                    + " FROM users left join users_roles on users.user_id = users_roles.user_id"
                    + " left join roles on users_roles.role_name = roles.role_name"
                    + " left join roles_permissions on roles.role_name = roles_permissions.role_name"
                    + " WHERE ";

    protected boolean enabledFlagUsed = true;

    // TODO : might be useful to make the User and Role classes pluggable.  Define an iface with the setter methods and use reflection to create a new instance.


    /**
     * Helper method for JDBI SQL Object.  Builds a single DefaultUserImpl with associated DefaultRoleImpl & Permission sub-graph
     * from tuples each of which was fetched into a UserRolePermissionJoinRow instance.
     *
     * @param i an iterator of the collection of UserRolePermissionJoinRow instances.
     * @return a new DefaultUserImpl instance with fields and Roles/Permissions set.
     */
    protected DefaultUserImpl extractObjectGraphFromJoinResults(Iterator<UserRolePermissionJoinRow> i) {
        DefaultUserImpl u = null;
        Map<String, ISecurityRole> roles = new HashMap<>();
        while (i.hasNext()) {
            UserRolePermissionJoinRow row = i.next();
            if (u == null) {
                u = new DefaultUserImpl();
                u.setId(row.getUserId());
                u.setUsername(row.getUsername());
                u.setPassword(row.getPassword());
            }
            // Could check that the user_id and username (etc.) are the same on all results.

            String roleName = row.getRoleName();
            String permission = row.getPermission();
            if (roleName != null) {
                if (!roles.containsKey(roleName)) {
                    roles.put(roleName, new DefaultRoleImpl(roleName));
                }
                if (permission != null) {
                    roles.get(roleName).getPermissions().add(permission);
                } else {
                    LOG.warn("Record found with null permission for role '{}'.", roleName);
                }
            } else if (permission != null) {
                LOG.warn("RoleName is null, but has a permission value of '{}'.  How can that be?", permission);
            }
        }
        if (u != null) {
            u.setRoles(new HashSet<>(roles.values()));
        }

        return u;
    }

    @SqlQuery(EnabledUserRolesPermissionsBaseSelectPrefix + "users.username = :username")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> findEnabledUsersWithRolesAndPermissions(@Bind("username") String username);

    @SqlQuery(UserRolesPermissionsBaseSelectPrefix + "users.username = :username")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> findUsersWithRolesAndPermissions(@Bind("username") String username);

    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public DefaultUserImpl findUser(String username) {
        checkArgument(!Strings.isNullOrEmpty(username), "findUser() requires a non-null, non-empty username parameter.");
        Iterator<UserRolePermissionJoinRow> baseResults = enabledFlagUsed
                ? findEnabledUsersWithRolesAndPermissions(username)
                : findUsersWithRolesAndPermissions(username);
        return extractObjectGraphFromJoinResults(baseResults);
    }

    @SqlQuery("SELECT user_Id AS id, username, password FROM users WHERE enabled AND username = :username")
    @MapResultAsBean
    protected abstract Iterator<DefaultUserImpl> findEnabledUsersWithoutRoles(@Bind("username") String username);

    @SqlQuery("SELECT user_Id AS id, username, password FROM users WHERE username = :username")
    @MapResultAsBean
    protected abstract Iterator<DefaultUserImpl> findUsersWithoutRoles(@Bind("username") String username);

    @Override
    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public DefaultUserImpl findUserWithoutRoles(String username) {
        checkArgument(!Strings.isNullOrEmpty(username),
                "findUserWithoutRoles() requires a non-null, non-empty username parameter.");
        DefaultUserImpl u = null;
        Iterator<DefaultUserImpl> users = isEnabledFlagUsed()
                ? findEnabledUsersWithoutRoles(username)
                : findUsersWithoutRoles(username);
        while (users != null && users.hasNext()) {
            if (u != null) {
                throw new AuthenticationException(
                        "Username must be unique in the backing store. Multiple users found for username " + username);
            }
            u = users.next();
        }
        return u;
    }

    @SqlQuery(EnabledRolesPermissionsBaseSelectPrefix + "users_roles.user_id = :userId")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> getEnabledUserRolesAndPermissions(@Bind("userId") Long userId);

    @SqlQuery(RolesPermissionsBaseSelectPrefix + "users_roles.user_id = :userId")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> getUserRolesAndPermissions(@Bind("userId") Long userId);

    /**
     * Fetches just the Roles associated with the corresponding DefaultUserImpl.
     *
     * @param userId the id of the user
     * @return the DefaultUserImpl's set of Roles or an empty Set.
     */
    @Override
    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public Set<ISecurityRole> getUserRoles(Long userId) {
        checkArgument(userId != null, "getUserRoles() requires a non-null userId parameter.");
        Iterator<UserRolePermissionJoinRow> baseResults = isEnabledFlagUsed()
                ? getEnabledUserRolesAndPermissions(userId)
                : getUserRolesAndPermissions(userId);
        DefaultUserImpl u = extractObjectGraphFromJoinResults(baseResults);
        return u != null ? u.getRoles() : Collections.<ISecurityRole>emptySet();
    }

    @Override
    public Set<ISecurityRole> getUserRoles(String username) {
        DefaultUserImpl u = findUser(username); // We'd need to do a 4-way join anyway, so just call findUser()
        return u != null ? u.getRoles() : Collections.<ISecurityRole>emptySet();
    }

    public DefaultUserImpl findUser(String username, boolean withRoles) {
        return withRoles ? findUser(username) : findUserWithoutRoles(username);
    }

    @SqlQuery(DefaultJdbiUserSecurityDAO.EnabledUserRolesPermissionsBaseSelectPrefix + "users.user_id = :userId")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> getUserWithRolesAndPermissions(@Bind("userId") Long userId);

    @Override
    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public DefaultUserImpl getUser(Long userId) {
        checkArgument(userId != null, "getUser() requires a non-null userId parameter.");
        return extractObjectGraphFromJoinResults(getUserWithRolesAndPermissions(userId));
    }

    @Override
    @SqlQuery("select username from users ORDER BY username")
    public abstract Iterator<String> findAllUsernames();

    @SqlUpdate("delete from users_roles where user_id = :userId")
    protected abstract void deleteUsersRoles(@Bind("userId") Long userId);

    @SqlUpdate("delete from users where user_id = :userId")
    protected abstract void deleteUserOnly(@Bind("userId") Long userId);

    @Override
    @Transaction
    public void deleteUser(Long userId) {
        checkArgument(userId != null, "deleteUser() requires a non-null userId parameter.");
        deleteUsersRoles(userId);
        deleteUserOnly(userId);
    }

    @SqlUpdate("insert into users (username, password) values (:username, :password)")
    protected abstract void createUserOnly(@Bind("username") String username, @Bind("password") String password);

    @SqlQuery("select user_id from users where username = :username")
    protected abstract Long fetchUserId(@Bind("username") String username);

    @SqlUpdate("insert into users_roles (user_id, role_name) values (:userId, :roleName)")
    protected abstract void createUserRole(@Bind("userId") Long userId, @Bind("roleName") String roleName);

    @Override
    @Transaction
    public Long createUser(DefaultUserImpl user) {
        checkNotNull(user, "createUser(), user parameter cannot be null.");
        checkArgument(user.getId() == null, "DefaultUserImpl's id field is assigned by the database and must be null.");
        Long userId;
        createUserOnly(user.getUsername(), user.getPassword());
        userId = fetchUserId(user.getUsername());
        user.setId(userId);
        for (ISecurityRole r : user.getRoles()) {
            createUserRole(userId, r.getName());
        }
        return userId;
    }

    @SqlUpdate("update users set username=:username, password=:password WHERE user_id=:userId")
    protected abstract void updateUserOnly(@Bind("userId") Long userId, @Bind("username") String username, @Bind("password") String password);

    @SqlUpdate("delete from users_roles where user_id = :userId AND role_name = :roleName")
    protected abstract void deleteAUserRole(@Bind("userId") Long userId, @Bind("roleName") String roleName);

    /**
     * Check if any of the persisted fields is different between the two DefaultUserImpl instances.
     *
     * @param u1 one DefaultUserImpl
     * @param u2 another DefaultUserImpl
     * @return true if username or password differs between u1 and u2;
     *         false if those fields are equal for the two DefaultUserImpl instances.
     */
    boolean needToUpdateUser(DefaultUserImpl u1, DefaultUserImpl u2) {
        return !Objects.equals(u1.getUsername(), u2.getUsername())
                || !Objects.equals(u1.getPassword(), u2.getPassword());
    }

    @Override
    @Transaction
    public void updateUser(DefaultUserImpl user) {
        checkNotNull(user, "updateUser(), user parameter cannot be null.");
        Long userId = user.getId();
        checkNotNull(userId, "updateUser(): DefaultUserImpl's userId field must not be null.");

        // The getUser() would be overkill except we need it to delta the Roles.
        DefaultUserImpl oldU = getUser(userId);
        checkNotNull(oldU, "No user with id='%s' in the database (updateUser does not perform createOrUpdate, maybe it should).", userId);

        // Compute deltas.
        // Since we had to fetch the user to delta the Roles, we may as well delta the fields to skip the base record update if it's not needed.
        if (needToUpdateUser(user, oldU)) {
            updateUserOnly(user.getId(), user.getUsername(), user.getPassword());
        }
        Set<ISecurityRole> rolesToRemove = Sets.difference(oldU.getRoles(), user.getRoles());
        if (rolesToRemove.size() > 0) {
            LOG.debug("Removing these Roles '{}' for user with id='{}'", rolesToRemove, userId);
        }
        for (ISecurityRole r : rolesToRemove) {
            deleteAUserRole(userId, r.getName());
        }
        Set<ISecurityRole> rolesToAdd = Sets.difference(user.getRoles(), oldU.getRoles());
        if (rolesToAdd.size() > 0) {
            LOG.debug("Adding these Roles '{}' for user with id='{}'", rolesToAdd, userId);
        }
        for (ISecurityRole r : rolesToAdd) {
            createUserRole(userId, r.getName());
        }
    }

    public boolean isEnabledFlagUsed() {
        return enabledFlagUsed;
    }

    public void setEnabledFlagUsed(boolean enabledFlagUsed) {
        this.enabledFlagUsed = enabledFlagUsed;
    }

}
