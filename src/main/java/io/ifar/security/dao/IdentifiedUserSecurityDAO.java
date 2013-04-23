package io.ifar.security.dao;

import io.ifar.security.realm.model.ISecurityRole;

import java.util.Set;

/**
 * An extention of the UserSecurityDAO that provides support for storing a numeric ISecurityUser identifier in the
 * Shiro PrincipalCollection.
 */
public interface IdentifiedUserSecurityDAO extends UserSecurityDAO {
    /**
     * Used to retrieve the Roles associated with an ISecurityUser when the principal stored in the session is a
     * numeric ISecurityUser identifier, such as the database primary key field.
     *
     * @param userId a numeric ISecurityUser identifier
     * @return the Set of Roles associated with the corresponding ISecurityUser
     */
    Set<ISecurityRole> getUserRoles(Long userId);
}
