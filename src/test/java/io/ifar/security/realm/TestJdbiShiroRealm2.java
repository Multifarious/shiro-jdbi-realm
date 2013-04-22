package io.ifar.security.realm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Project: security
 * DefaultUserImpl: ezra
 * Date: 4/3/13
 */
public class TestJdbiShiroRealm2 extends TestJdbiShiroRealm {

    private static final Logger LOG = LoggerFactory.getLogger(TestJdbiShiroRealm2.class);

    protected Logger log()
    {
        return LOG;
    }

    protected String getUsername()
    {
        return "ShiroTest_id_uname";
    }

    // We expect secondary principal values are optional and not used for authZ functionality that is under test.
    // This class tests that.
    protected void configureRealm(JdbiShiroRealm realm) {
        realm.setPrincipalValueFields(Arrays.asList(JdbiShiroRealm.PrincipalValueField.USER_ID, JdbiShiroRealm.PrincipalValueField.USERNAME));
    }

}
