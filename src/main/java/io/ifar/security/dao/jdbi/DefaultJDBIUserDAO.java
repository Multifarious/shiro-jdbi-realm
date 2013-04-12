package io.ifar.security.dao.jdbi;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

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
import io.ifar.security.realm.model.Role;
import io.ifar.security.realm.model.User;

import java.util.*;


/**
 * Implementation of UserDAO via DBI.
 */
public abstract class DefaultJDBIUserDAO implements UserDAO, Transactional<DefaultJDBIUserDAO> {

    private final static String UserRolesPermissionsBaseSelectPrefix =
            "SELECT users.user_Id AS userId, users.username AS username, users.password AS password,"
                    + " roles.role_name AS roleName, roles_permissions.permission AS permission"
                    + " FROM users left join users_roles on users.user_id = users_roles.user_id"
                    + " left join roles on users_roles.role_name = roles.role_name"
                    + " left join roles_permissions on roles.role_name = roles_permissions.role_name";

    private final static String RolesPermissionsBaseSelectPrefix =
            "SELECT roles.role_name AS roleName, roles_permissions.permission AS permission"
                    + " FROM users_roles left join roles on users_roles.role_name = roles.role_name"
                    + " left join roles_permissions on roles.role_name = roles_permissions.role_name";

    private final static Logger LOG = LoggerFactory.getLogger(DefaultJDBIUserDAO.class);

    @SqlQuery(UserRolesPermissionsBaseSelectPrefix + " WHERE users.user_id = :userId")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> getUserWithRolesAndPermissions(@Bind("userId") Long userId);

    @SqlQuery(UserRolesPermissionsBaseSelectPrefix + " WHERE users.username = :username")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> findUserWithRolesAndPermissions(@Bind("username") String username);

    /**
     * Helper method for JDBI SQL Object.  Builds a single User with associated Role & Permission sub-graph
     * from tuples each of which was fetched into a UserRolePermissionJoinRow instance.
     *
     * @param i an iterator of the collection of UserRolePermissionJoinRow instances.
     * @return a new User instance with fields and Roles/Permissions set.
     */
    protected User extractObjectGraphFromJoinResults(Iterator<UserRolePermissionJoinRow> i) {
        User u = null;
        Map<String, Role> roles = new HashMap<>();
        while (i.hasNext()) {
            UserRolePermissionJoinRow row = i.next();
            if (u == null) {
                u = new User();
                u.setId(row.getUserId());
                u.setUsername(row.getUsername());
                u.setPassword(row.getPassword());
            }
            // Could check that the user_id and username (etc.) are the same on all results.

            String roleName = row.getRoleName();
            String permission = row.getPermission();
            if (roleName != null) {
                if (!roles.containsKey(roleName)) {
                    roles.put(roleName, new Role(roleName));
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

    @Override
    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public User getUser(Long userId) {
        checkArgument(userId != null, "getUser() requires a non-null userId parameter.");
        return extractObjectGraphFromJoinResults(getUserWithRolesAndPermissions(userId));
    }

    @Override
    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public User findUser(String username) {
        checkArgument(!Strings.isNullOrEmpty(username), "findUser() requires a non-null, non-empty username parameter.");
        return extractObjectGraphFromJoinResults(findUserWithRolesAndPermissions(username));
    }

    @SqlQuery("SELECT user_Id AS id, username, password FROM users WHERE username = :username")
    @MapResultAsBean
    protected abstract User findUserWithoutRoles(@Bind("username") String username);

    @Override
    public User findUser(String username, boolean withRoles) {
        return withRoles ? findUser(username) : findUserWithoutRoles(username);
    }

    @SqlQuery(RolesPermissionsBaseSelectPrefix + " WHERE users_roles.user_id = :userId")
    @MapResultAsBean
    protected abstract Iterator<UserRolePermissionJoinRow> getUserRolesAndPermissions(@Bind("userId") Long userId);

    /**
     * Fetches just the Roles associated with the corresponding User.
     * @param userId the id of the user
     * @return the User's set of Roles or an empty Set.
     */
    @Override
    @Transaction(value = TransactionIsolationLevel.READ_COMMITTED)
    public Set<Role> getUserRoles(Long userId)
    {
        User u = extractObjectGraphFromJoinResults(getUserRolesAndPermissions(userId));
        return u != null ? u.getRoles() : Collections.<Role>emptySet();
    }

    @Override
    public Set<Role> getUserRoles(String username)
    {
        User u = findUser(username); // We'd need to do a 4-way join anyway, so just call findUser()
        return u != null ? u.getRoles() : Collections.<Role>emptySet();
    }


    // Set<User> getAllUsers();

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
    public Long createUser(User user) {
        checkNotNull(user, "createUser(), user parameter cannot be null.");
        checkArgument(user.getId() == null, "User's id field is assigned by the database and must be null.");
        Long userId;
        createUserOnly(user.getUsername(), user.getPassword());
        userId = fetchUserId(user.getUsername());
        user.setId(userId);
        for (Role r : user.getRoles()) {
            createUserRole(userId, r.getName());
        }
        return userId;
    }


    // @Override
    // @SqlUpdate("update users set password=:newPassword WHERE user_id=:userId")
    // public abstract void updateUserPassword(@Bind("userId") Long userId, @Bind("newPassword") String newPw);


    @SqlUpdate("update users set username=:username, password=:password WHERE user_id=:userId")
    protected abstract void updateUserOnly(@Bind("userId") Long userId, @Bind("username") String username, @Bind("password") String password);

    @SqlUpdate("delete from users_roles where user_id = :userId AND role_name = :roleName")
    protected abstract void deleteAUserRole(@Bind("userId") Long userId, @Bind("roleName") String roleName);

    /**
     * Check if any of the persisted fields is different between the two User instances.
     *
     * @param u1 one User
     * @param u2 another User
     * @return true if username or password differs between u1 and u2;
     *         false if those fields are equal for the two User instances.
     */
    boolean needToUpdateUser(User u1, User u2) {
        return !Objects.equals(u1.getUsername(), u2.getUsername())
                || !Objects.equals(u1.getPassword(), u2.getPassword());
    }

    @Override
    @Transaction
    public void updateUser(User user) {
        checkNotNull(user, "updateUser(), user parameter cannot be null.");
        Long userId = user.getId();
        checkNotNull(userId, "updateUser(): User's userId field must not be null.");

        // The getUser() would be overkill except we need it to delta the Roles.
        User oldU = getUser(userId);
        checkNotNull(oldU, "No user with id='%s' in the database (updateUser does not perform createOrUpdate, maybe it should).", userId);

        // Compute deltas.
        // Since we had to fetch the user to delta the Roles, we may as well delta the fields to skip the base record update if it's not needed.
        if (needToUpdateUser(user, oldU)) {
            updateUserOnly(user.getId(), user.getUsername(), user.getPassword());
        }
        Set<Role> rolesToRemove = Sets.difference(oldU.getRoles(), user.getRoles());
        if (rolesToRemove.size() > 0) {
            LOG.debug("Removing these Roles '{}' for user with id='{}'", rolesToRemove, userId);
        }
        for (Role r : rolesToRemove) {
            deleteAUserRole(userId, r.getName());
        }
        Set<Role> rolesToAdd = Sets.difference(user.getRoles(), oldU.getRoles());
        if (rolesToAdd.size() > 0) {
            LOG.debug("Adding these Roles '{}' for user with id='{}'", rolesToAdd, userId);
        }
        for (Role r : rolesToAdd) {
            createUserRole(userId, r.getName());
        }
    }

}
