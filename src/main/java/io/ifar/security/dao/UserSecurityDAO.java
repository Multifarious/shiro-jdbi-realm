package io.ifar.security.dao;

import io.ifar.security.realm.model.ISecurityRole;
import io.ifar.security.realm.model.ISecurityUser;

import java.util.Set;

/**
 * A DAO API that exposes a minimal surface needed to support a Shiro AuthorizingRealm implementation.
 */
public interface UserSecurityDAO {

    /**
     * Lookup by username.  Usernames must be unique across DefaultUserImpl records in the backing store.
     */
    ISecurityUser findUserWithoutRoles(String username);

    /**
     * Used to retrieve the Roles associated with a DefaultUserImpl when the principal stored in the session is a numeric DefaultUserImpl
     * identifier, such as a database primary key field.
     *
     * @param userId a numeric DefaultUserImpl identifier
     * @return the Set of Roles associated with the corresponding DefaultUserImpl
     */
    Set<ISecurityRole> getUserRoles(Long userId);

    /**
     * Used to retrieve the Roles associated with a DefaultUserImpl when the principal stored in the session is a string DefaultUserImpl
     * identifier, such as the username used for authentication during login.
     *
     * @param username a string DefaultUserImpl identifier - typically the username used when the DefaultUserImpl is authenticated
     * @return the Set of Roles associated with the corresponding DefaultUserImpl
     */
    Set<ISecurityRole> getUserRoles(String username);

}
