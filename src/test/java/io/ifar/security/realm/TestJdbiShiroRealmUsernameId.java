package io.ifar.security.realm;

import io.ifar.security.realm.model.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Arrays.*;
import java.util.HashSet;
import java.util.Set;

/**
 * Project: security
 * User: ezra
 * Date: 4/3/13
 */
public class TestJdbiShiroRealmUsernameId extends TestJdbiShiroRealmUsername {

    private static final Logger LOG = LoggerFactory.getLogger(TestJdbiShiroRealmUsernameId.class);

    protected Logger log()
    {
        return LOG;
    }

    protected String getUsername()
    {
        return "ShiroTest_uname_id";
    }

    protected String[] getExpectedPermissions() {
        return new String[]{"super", "foo", "bar"};
    }

    protected Set<Role> getRoles()
    {
        // Permissions aren't involved in user creation, just the role name
        return new HashSet<>(asList(new Role("admin"), new Role("user")));
    }

    // Should be fine to have the username be the principal.
    protected void configureRealm(JdbiShiroRealm realm) {
        realm.setPrincipalValueFields(asList(JdbiShiroRealm.PrincipalValueField.USERNAME, JdbiShiroRealm.PrincipalValueField.USER_ID));
    }

}
