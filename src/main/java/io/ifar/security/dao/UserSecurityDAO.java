package io.ifar.security.dao;

import io.ifar.security.realm.model.Role;
import io.ifar.security.realm.model.User;

import java.util.Set;

/**
 *
 */
public interface UserSecurityDAO {

    /**
     * Lookup by username.  Usernames must be unique across User records in the backing store.
     */
    User findUserWithoutRoles(String username);

    /**
     * Used to retrieve the Roles associated with a User when the principal stored in the session is a numeric User
     * identifier, such as a database primary key field.
     *
     * @param userId a numeric User identifier
     * @return the Set of Roles associated with the corresponding User
     */
    Set<Role> getUserRoles(Long userId);

    /**
     * Used to retrieve the Roles associated with a User when the principal stored in the session is a string User
     * identifier, such as the username used for authentication during login.
     *
     * @param username a string User identifier - typically the username used when the User is authenticated
     * @return the Set of Roles associated with the corresponding User
     */
    Set<Role> getUserRoles(String username);

}
