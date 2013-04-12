package io.ifar.security.dao;

import io.ifar.security.realm.model.Role;

/**
 * No API to change a Role's name.
 *
 * TODO - we need an implementation of this if we want to be able to programmatically manage (Create/Update/Delete) Roles & Permissions
 */
public interface RoleDAO {

    /**
     * Persist the named Role and associated Permissions.
     * @param role A Role object and associated Permissions.
     */
    void createRole(Role role);

    /**
     * Fetch the named Role and associated Permissions.
     */
    Role getRole(String roleName);

    /**
     * Change the set of Permissions associated with this Role.
     * Note, the Role's name is the primary key and is not changed.
     * @param role  Role with Permissions to update.
     */
    void updateRole(Role role);

    /**
     * Delete the named Role and its associated Permissions.
     * @param roleName name of the Role to delete.
     */
    void deleteRole(String roleName);

}
