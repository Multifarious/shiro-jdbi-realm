package io.ifar.security.realm.model;

import java.util.Set;

/**
 * Shiro uses Role-based security.  A Role has a name and a collection of associated string-values Permissions.
 */
public interface ISecurityRole {
    /**
     * Roles are named.
     * @return  the Role's name.
     */
    String getName();

    /**
     * Roles have associated string-value Permissions.
     * @return  the set of associated Permissions.
     */
    Set<String> getPermissions();
}
