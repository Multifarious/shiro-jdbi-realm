package io.ifar.security.dao;

import io.ifar.security.realm.model.ISecurityRole;
import io.ifar.security.realm.model.ISecurityUser;

import java.util.Set;

/**
 * An extention of the UserSecurityDAO that provides support for storing a numeric ISecurityUser identifier in the
 * Shiro PrincipalCollection.
 */
public interface IdentifiedUserSecurityDAO extends UserSecurityDAO {
    /**
     * Used to retrieve the Roles associated with an {@link ISecurityUser} when the principal stored in the session is
     * a numeric {@link ISecurityUser} identifier, such as the value returned from
     * {@link ISecurityUser#getId()}.
     * <p>
     *     If using a {@link io.ifar.security.realm.JdbiShiroRealm} and the first of the
     *     {@link io.ifar.security.realm.JdbiShiroRealm#getPrincipalValueFields()} is the
     *     {@link io.ifar.security.realm.JdbiShiroRealm.PrincipalValueField#USER_ID}, then the DAO implementation
     *     used by the {@code JdbiShiroRealm} must implement this interface in order to handle
     *     authorization requests.
     * </p>
     *
     * @param userId a numeric ISecurityUser identifier
     * @return the Set of Roles associated with the corresponding ISecurityUser
     */
    Set<ISecurityRole> getUserRoles(Long userId);
}
