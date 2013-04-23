package io.ifar.security.dao;

import io.ifar.security.dao.jdbi.DefaultUserImpl;

import java.util.Iterator;

/**
 * Data Access Object for DefaultUserImpl instances.
 *
 * The UserDAO supports create/update/delete operations for DefaultUserImpl objects and association of same with DefaultRoleImpl objects.
 * Note that it does not, however, support management of the DefaultRoleImpl objects themselves nor the associated Permissions.
 */
public interface UserDAO extends UserSecurityDAO {

    /**
     * Get by primary key value.
     */
     DefaultUserImpl getUser(Long userId);

    /**
     * Lookup by username.  Return the associated Roles if the withRoles argument is true; otherwise
     * just fetch the non-Collection DefaultUserImpl fields: id and password.
     */
    DefaultUserImpl findUser(String username, boolean withRoles);

    Iterator<String> findAllUsernames();

    /**
     * Persist the user in the backing data store.  Create associations with the indicated Roles.
     * DefaultUserImpl's userId will be generated and assigned if not provided.
     * @param user The DefaultUserImpl object to persist.  Its userId is normally null when calling this method.
     * @return the newly persisted DefaultUserImpl object's id which is also set on the object's id field.
     */
    Long createUser(DefaultUserImpl user);

    /**
     * Delete associated DefaultUserImpl object and any associations to its Roles from the backing store.
     * @param userId the user to delete
     */
    void deleteUser(Long userId);

    /**
     * Update the DefaultUserImpl record in the backing store.  Operation may be conditional, occurring only if the value of one or more
     * persisted fields has changed.  The persistent association to Roles is also updated to reflect the current
     * state of the DefaultUserImpl provided as a parameter.
     */
    void updateUser(DefaultUserImpl user);
}