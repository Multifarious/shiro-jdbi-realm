package io.ifar.security.realm;

import io.ifar.security.dao.jdbi.DatabaseUtils;
import io.ifar.security.dao.jdbi.DefaultRoleImpl;
import io.ifar.security.dao.jdbi.DefaultUserImpl;
import io.ifar.security.realm.model.ISecurityRole;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.Subject;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * DefaultUserImpl: ezra
 * Date: 3/26/13
 */
public class TestJdbiShiroRealm extends AbstractShiroTest {

    private static final Logger LOG = LoggerFactory.getLogger(TestJdbiShiroRealm.class);

    protected static DatabaseUtils harness = new DatabaseUtils();

    protected static JdbiShiroRealm realm;

    protected void configureRealm(JdbiShiroRealm realm) {
    }

    protected String[] getExpectedPermissions() {
        return new String[]{"bar"};
    }

    protected String getUsername() {
        return "ShiroTest";
    }

    protected String getPlainTextPassword() {
        return "AClearPassword#123";
    }

    protected Set<ISecurityRole> getRoles() {
        // Permissions aren't involved in user creation, just the role name
        return Collections.<ISecurityRole>singleton(new DefaultRoleImpl("user"));
    }

    protected Logger log()
    {
        return LOG;
    }

    private void setupRealm() {
        realm = new JdbiShiroRealm(harness.getDbi());
        realm.setCredentialsMatcher(passwordMatcher);  // NOT NEEDED.  Default works fine for parsing pws.
        configureRealm(realm);
        log().info("Using principal values: {}", realm.getPrincipalValueFields());
        getSecurityManager().setRealm(realm);
    }

    @BeforeClass
    public static void setup() {
        harness.setUp();
        AbstractShiroTest.setupShiro();
    }

    @AfterClass
    public static void tearDown() {
        AbstractShiroTest.tearDownShiro();
        harness.getDbi().close(realm.getUserSecurityDAO());
        harness.tearDown();
        realm = null;
    }

    @Before
    public void preTest() {
        if (realm == null) {
            setupRealm();
        }
    }

    protected void checkExpectedPermissions(String[] expectedPermissions, Collection<String> perms) {
        assertTrue("Expect " + expectedPermissions.length + " permission(s).", perms.size() == expectedPermissions.length);
        for (String perm : expectedPermissions) {
            assertTrue("Expect the '" + perm + "' permission to be assigned.", perms.contains(perm));
        }

    }

    protected void checkIsPermitted(String[] expectedPermissions, Subject currentUser) {
        for (String perm : expectedPermissions) {
            assertTrue("Expected permission: " + perm, currentUser.isPermitted(perm));
        }
    }

    protected void checkIsNotPermitted(String[] expectedPermissions, Subject currentUser) {
        for (String perm : expectedPermissions) {
            assertFalse("Expected permission: " + perm, currentUser.isPermitted(perm));
        }
    }

    protected DefaultUserImpl fetchOrCreateUser() {
        DefaultUserImpl u = harness.getUserDAO().findUser(getUsername());
        if (u == null) {
            // We don't modify this user during tests, so if it already exists, just use it as-is. Otherwise:
            String hashedPw = passwordService.encryptPassword(getPlainTextPassword());
            u = new DefaultUserImpl(null, getUsername(), hashedPw, getRoles());
            // LOG.trace("Parsably hashed password: pw={}; hash={}", getPlainTextPassword(), hashedPw);
            harness.getUserDAO().createUser(u);
            assertNotNull(u.getId());  // persisted
        }
        return u;
    }

    protected void checkStoredPrincipal(DefaultUserImpl u, Object p) {
        assertEquals("CurrentUser is expected to store the user's id as the principal.", u.getId(), p);
    }

    @Test
    public void loginTest() {
        DefaultUserImpl u = fetchOrCreateUser();
        log().info("User under test: {}", u);
        log().info("Hashed password: {}", u.getPassword());

        setSubject(new Subject.Builder(getSecurityManager()).buildSubject());
        Subject currentUser = getSubject();
        if (!currentUser.isAuthenticated()) {
            // This is what would be provided on login.
            UsernamePasswordToken upToken = new UsernamePasswordToken(getUsername(), getPlainTextPassword());
            currentUser.login(upToken);
            assertTrue(currentUser.isAuthenticated());
        }
        checkStoredPrincipal(u, currentUser.getPrincipal());
        currentUser.logout();
    }

    @Test
    public void authenticateTest() {
        DefaultUserImpl u = fetchOrCreateUser();
        // This is what would be provided on login.
        UsernamePasswordToken upToken = new UsernamePasswordToken(u.getUsername(), getPlainTextPassword());
        getSecurityManager().authenticate(upToken);
    }

    @Test(expected = AuthenticationException.class)
    public void wrongPassword() {
        DefaultUserImpl u = fetchOrCreateUser();
        // This is what would be provided on login with the wrong password.
        UsernamePasswordToken upToken = new UsernamePasswordToken(u.getUsername(), "WrongPasssord");
        getSecurityManager().authenticate(upToken);
    }

    @Test(expected = AuthenticationException.class)
    public void preHashedPassword() {
        DefaultUserImpl u = fetchOrCreateUser();
        // This is what would be provided on login with the wrong password.
        UsernamePasswordToken upToken = new UsernamePasswordToken(u.getUsername(), u.getPassword());
        getSecurityManager().authenticate(upToken);
    }

    @Test
    public void noSuchUser() {
        // Ensure (a) user exists.
        fetchOrCreateUser();
        // This is what would be provided on login.
        UsernamePasswordToken upToken = new UsernamePasswordToken("NoSuchUser", getPlainTextPassword());
        AuthenticationInfo authNInfo = realm.doGetAuthenticationInfo(upToken);
        assertNull(authNInfo);
    }

    @Test(expected = AuthenticationException.class)
    public void noSuchUser_login() {
        // Ensure (a) user exists.
        fetchOrCreateUser();
        // This is what would be provided on login with the wrong password.
        UsernamePasswordToken upToken = new UsernamePasswordToken("NoOneByThatName", getPlainTextPassword());
        getSecurityManager().authenticate(upToken);
    }

    @Test(expected = AuthenticationException.class)
    public void noUsername() {
        // Ensure (a) user exists.
        fetchOrCreateUser();

        // This is what would be provided on login.
        UsernamePasswordToken upToken = new UsernamePasswordToken("", getPlainTextPassword());
        getSecurityManager().authenticate(upToken);
    }

    @Test
    public void authZAUserWithHashedPass() {
        DefaultUserImpl u = fetchOrCreateUser();

        // This is what would be provided on login.
        UsernamePasswordToken upToken = new UsernamePasswordToken(u.getUsername(), getPlainTextPassword());
        AuthenticationInfo authNInfo = realm.doGetAuthenticationInfo(upToken);

        AuthorizationInfo authZInfo = realm.doGetAuthorizationInfo(authNInfo.getPrincipals());
        Collection<String> rolesC = authZInfo.getRoles();
        assertTrue("Expect different number of roles.", rolesC.size() == getRoles().size());
        assertTrue("Expect different role to be assigned.", rolesC.contains(getRoles().iterator().next().getName()));

        checkExpectedPermissions(getExpectedPermissions(), authZInfo.getStringPermissions());
    }

    @Test
    public void authorizeUser() {
        DefaultUserImpl u = fetchOrCreateUser();

        Subject currentUser = getSubject();
        if (!currentUser.isAuthenticated()) {
            // This is what would be provided on login.
            UsernamePasswordToken upToken = new UsernamePasswordToken(getUsername(), getPlainTextPassword());
            currentUser.login(upToken);
            assertTrue(currentUser.isAuthenticated());
        }
        log().info("Primary principal: {}", currentUser.getPrincipal());
        checkStoredPrincipal(u, currentUser.getPrincipal());

        log().info("All principal values: {}", currentUser.getPrincipals());

        checkIsPermitted(getExpectedPermissions(), currentUser);
        assertTrue(currentUser.hasRole(getRoles().iterator().next().getName()));

        currentUser.logout();
    }

    @Test
    public void authorizeUserNoRoles() {
        String usernm = getUsername() + "_x";
        DefaultUserImpl u = harness.getUserDAO().findUser(usernm);
        if (u == null) {
            // We don't modify this user during tests, so if it already exists, just use it as-is. Otherwise:
            u = new DefaultUserImpl(null, usernm, passwordService.encryptPassword(getPlainTextPassword()), null);
            u.setId(harness.getUserDAO().createUser(u));
            assertNotNull(u.getId());  // persisted
        }
        Subject currentUser = getSubject();
        if (!currentUser.isAuthenticated()) {
            // This is what would be provided on login.
            UsernamePasswordToken upToken = new UsernamePasswordToken(usernm, getPlainTextPassword());
            currentUser.login(upToken);
            assertTrue(currentUser.isAuthenticated());
        } else {
            log().error("DefaultUserImpl should not be authenticated at this point.");
            throw new RuntimeException("DefaultUserImpl was authenticated before login !?!");
        }
        checkStoredPrincipal(u, currentUser.getPrincipal());

        checkIsNotPermitted(getExpectedPermissions(), currentUser);
        assertFalse(currentUser.hasRole("user"));

        currentUser.logout();

        harness.getUserDAO().deleteUser(u.getId());
    }

}
