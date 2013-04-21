package io.ifar.security.dao;

import io.ifar.security.realm.model.*;

import java.util.Iterator;
import java.util.Set;

/**
 * Data Access Object for User instances.
 *
 * The UserDAO supports create/update/delete operations for User objects and association of same with Role objects.
 * Note that it does not, however, support management of the Role objects themselves nor the associated Permissions.
 */
public interface UserDAO extends UserSecurityDAO {

    /**
     * Get by primary key value.
     */
    User getUser(Long userId);

    /**
     * Lookup by username.  Return the associated Roles if the withRoles argument is true; otherwise
     * just fetch the non-Collection User fields: id and password.
     */
    User findUser(String username, boolean withRoles);

    Iterator<String> findAllUsernames();

    /**
     * Persist the user in the backing data store.  Create associations with the indicated Roles.
     * User's userId will be generated and assigned if not provided.
     * @param user The User object to persist.  Its userId is normally null when calling this method.
     * @return the newly persisted User object's id which is also set on the object's id field.
     */
    Long createUser(User user);

    /**
     * Delete associated User object and any associations to its Roles from the backing store.
     * @param userId the user to delete
     */
    void deleteUser(Long userId);

    /**
     * Update the User record in the backing store.  Operation may be conditional, occurring only if the value of one or more
     * persisted fields has changed.  The persistent association to Roles is also updated to reflect the current
     * state of the User provided as a parameter.
     */
    void updateUser(User user);

    // void updateUserPassword(Long userId, String newPw);
}