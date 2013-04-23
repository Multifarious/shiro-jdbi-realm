package io.ifar.security.dao;

import io.ifar.security.realm.model.ISecurityRole;
import io.ifar.security.realm.model.ISecurityUser;

import java.util.Set;

/**
 * A DAO API that exposes a minimal surface needed to support a Shiro AuthorizingRealm implementation.
 */
public interface UserSecurityDAO {

    /**
     * Lookup by username.  Usernames must be unique across ISecurityUser records in the backing store.
     */
    ISecurityUser findUserWithoutRoles(String username);

    /**
     * Used to retrieve the Roles associated with a ISecurityUser when the principal stored in the session is a string
     * ISecurityUser identifier, such as the username used for authentication during login.
     *
     * @param username a string ISecurityUser identifier - typically the username used when the ISecurityUser is authenticated
     * @return the Set of Roles associated with the corresponding ISecurityUser
     */
    Set<ISecurityRole> getUserRoles(String username);

}
