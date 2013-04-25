package io.ifar.security.dao;

import io.ifar.security.realm.model.ISecurityRole;
import io.ifar.security.realm.model.ISecurityUser;

import java.util.Set;

/**
 * A DAO API that exposes a minimal surface needed to support a Shiro AuthorizingRealm implementation.
 */
public interface UserSecurityDAO {

    /**
     * Lookup by username.  Usernames must be unique across {@link ISecurityUser} records in the backing store.
     */
    ISecurityUser findUserWithoutRoles(String username);

    /**
     * Used to retrieve the Roles associated with a {@link ISecurityUser} when the principal stored in the session is a
     * string {@link ISecurityUser} identifier, such as the username used for authentication during login.  The value
     * itself is taken from the {@link ISecurityUser#getUsername()} method.
     * <p>
     *     If using a DAO implementation that only supports this interface and not the
     * </p>
     *
     * @param username a string {@link ISecurityUser} identifier - typically the username used when the
     *                 {@link ISecurityUser} is authenticated
     * @return the Set of Roles associated with the corresponding ISecurityUser
     */
    Set<ISecurityRole> getUserRoles(String username);

}
