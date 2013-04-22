package io.ifar.security.realm;

import io.ifar.security.dao.jdbi.DefaultRoleImpl;
import io.ifar.security.dao.jdbi.DefaultUserImpl;
import io.ifar.security.realm.model.ISecurityRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * Project: security
 * DefaultUserImpl: ezra
 * Date: 4/3/13
 */
public class TestJdbiShiroRealmUsername extends TestJdbiShiroRealm {

    private static final Logger LOG = LoggerFactory.getLogger(TestJdbiShiroRealmUsername.class);

    protected Logger log()
    {
        return LOG;
    }

    protected String getUsername()
    {
        return "ShiroTest_uname";
    }

    protected String[] getExpectedPermissions() {
        return new String[]{"super", "foo"};
    }

    protected String getPlainTextPassword()
    {
        return "AClearPassword#456";
    }

    protected Set<ISecurityRole> getRoles()
    {
        // Permissions aren't involved in user creation, just the role name
        return Collections.<ISecurityRole>singleton(new DefaultRoleImpl("admin"));
    }

    // Should be fine to have the username be the principal.
    protected void configureRealm(JdbiShiroRealm realm) {
        realm.setPrincipalValueFields(Arrays.asList(JdbiShiroRealm.PrincipalValueField.USERNAME));
    }

    protected void checkStoredPrincipal(DefaultUserImpl u, Object p) {
        assertEquals("CurrentUser is expected to store the user's username as the principal.", u.getUsername(), p);
    }

}
