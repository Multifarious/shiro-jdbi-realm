package io.ifar.security.dao.jdbi;

import static org.junit.Assert.*;

import org.junit.*;
import org.skife.jdbi.v2.exceptions.UnableToExecuteStatementException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.ifar.security.realm.model.Role;
import io.ifar.security.realm.model.User;

import java.sql.SQLException;
import java.util.Collections;

public class TestUserDAO {

    private static final Logger LOG = LoggerFactory.getLogger(TestUserDAO.class);

    private static final DatabaseUtils harness = new DatabaseUtils();

    @BeforeClass
    public static void setupDao() {
        harness.setUp();
    }

    @AfterClass
    public static void tearDownDao() {
        harness.tearDown();
    }

    @Test
    public void getFirstUser() throws SQLException
    {
        User u = harness.getUserDAO().findUser("TEST");
        assertNotNull(u);
        assertEquals(2l, u.getRoles().size());

        LOG.info("The TEST user: {}", u);
    }

    @Test
    public void getFirstUser_withoutRoles() throws SQLException
    {
        User u = harness.getUserDAO().findUser("TEST", false);
        assertNotNull(u);
        assertEquals(0l, u.getRoles().size());

        LOG.info("The TEST user (without Roles): {}", u);
    }

    @Test
    public void createAUser() // throws SQLException;
    {
        User u = harness.getUserDAO().findUser("FOO");
        if (u != null)
        {
            harness.getUserDAO().deleteUser(u.getId());
        }
        Role r = new Role("user", Collections.singleton("bar"));
        u = new User(null, "FOO", "PASSWORD", Collections.singleton(r));
        Long newId = harness.getUserDAO().createUser(u);
        assertNotNull(newId);
        assertEquals(newId, u.getId());

        LOG.info("Freshly minted user: {}", u);

        User fromDb = harness.getUserDAO().findUser("FOO");
        assertEquals(u, fromDb);
        assertEquals(u.getRoles(), fromDb.getRoles());

        harness.getUserDAO().deleteUser(newId);
    }

    /**
     * user with no permissions
     */
    @Test
    public void createUser_noRoles() // throws SQLException;
    {
        User u = harness.getUserDAO().findUser("FOO");
        if (u != null)
        {
            harness.getUserDAO().deleteUser(u.getId());
        }
        u = new User(null, "FOO", "PASSWORD", null);
        Long newId = harness.getUserDAO().createUser(u);
        assertNotNull(newId);
        assertEquals(newId, u.getId());
        assertEquals(0, u.getRoles().size());

        LOG.info("Freshly minted user (no roles): {}", u);

        User fromDb = harness.getUserDAO().findUser("FOO");
        assertEquals(u, fromDb);
        assertEquals(u.getRoles(), fromDb.getRoles());

        harness.getUserDAO().deleteUser(newId);
    }


    // test creating a user with a non-existent role - should happen IFF db has FKs.  Expect: fail
    @Test(expected = UnableToExecuteStatementException.class)
    public void createUser_noSuchRole() // throws SQLException;
    {
        User u = harness.getUserDAO().findUser("FOO");
        if (u != null)
        {
            harness.getUserDAO().deleteUser(u.getId());
        }
        Role r = new Role("fakey", Collections.singleton("blah"));
        u = new User(null, "FOO", "PASSWORD", Collections.singleton(r));

        // THIS should fail in DBs that support FK constraints.
        Long newId = harness.getUserDAO().createUser(u);
        assertNotNull("UserId assigned during creation.", newId);
        assertEquals(newId, u.getId());

        LOG.info("Freshly minted user: {}", u);

        User fromDb = harness.getUserDAO().findUser("FOO");
        assertEquals("UserId and username match.", u, fromDb);

        // IN other DBs it fails here.  Oops
        assertEquals("Roles correctly persisted to DB.", u.getRoles(), fromDb.getRoles());

        harness.getUserDAO().deleteUser(newId);
    }


    /**
     * Not sure why we'd ever do this...
     */
    @Test(expected = IllegalArgumentException.class)
    public void createUser_IdSpecified() // throws SQLException;
    {
        User u = harness.getUserDAO().findUser("FOO");
        if (u != null)
        {
            harness.getUserDAO().deleteUser(u.getId());
        }
        Role r = new Role("user", Collections.singleton("bar"));
        u = new User(1001l, "FOO", "PASSWORD", Collections.singleton(r));
        harness.getUserDAO().createUser(u);
    }

    /**
     * Not sure why we'd ever do this...
     */
    @Test(expected = UnableToExecuteStatementException.class)
    public void createUser_valueTooLongForColumn() // throws SQLException;
    {
        User u = harness.getUserDAO().findUser("FOO");
        if (u != null) {
            harness.getUserDAO().deleteUser(u.getId());
        }
        Role r = new Role("user", Collections.singleton("bar"));
        u = new User(null, "FOO",
                "A_TOO_LONG_PASSWORD"
                        + "_0123456789_0123456789_0123456789_0123456789_0123456789"
                        + "_0123456789_0123456789_0123456789_0123456789_0123456789"
                        + "_0123456789_0123456789_0123456789_0123456789_0123456789"
                        + "_0123456789_0123456789_0123456789_0123456789_0123456789"
                        + "_0123456789_0123456789_0123456789_0123456789_0123456789"
                        + "_0123456789_0123456789_0123456789_0123456789_0123456789"
                , Collections.singleton(r));
        // Should throw...
        Long newId = harness.getUserDAO().createUser(u);
        // clean-up incase this test-case fails (e.g., db silently truncates)
        assertNotNull(newId);
        harness.getUserDAO().deleteUser(newId);
    }

    @Test
    public void deleteAUser()
    {
        User aU = harness.getUserDAO().getUser(102l);
        assertEquals("Username is 'Arnold'", "Arnold", aU.getUsername());
        harness.getUserDAO().deleteUser(102l);
        assertNull("No such user expect in DB after delete.", harness.getUserDAO().getUser(102l));
    }

    @Test
    public void testNeedToUpdateUser()
    {
        User u1 = new User(null, "A", "B", null);
        User u2 = new User(null, "A", "B", null);

        assertTrue(!harness.getUserDAO().needToUpdateUser(u1, u2));
        u2.setUsername("Q");
        assertTrue(harness.getUserDAO().needToUpdateUser(u1, u2));
        u2.setUsername("A");
        u2.setPassword("Q");
        assertTrue(harness.getUserDAO().needToUpdateUser(u1, u2));
    }

    @Test
    public void updateAUser()
    {
        User u = harness.getUserDAO().findUser("TEST");

        Role adminRole = null;
        for (Role r : u.getRoles())
        {
            if ("admin".equals(r.getName()))
            {
                adminRole = r;
                break;
            }
        }
        u.getRoles().remove(adminRole);
        Role otherRole = new Role("other", Collections.singleton("gee"));
        u.getRoles().add(otherRole);

        harness.getUserDAO().updateUser(u);

        User inDb = harness.getUserDAO().getUser(u.getId());
        LOG.info("Updated user: {}", inDb);

        assertEquals(2, inDb.getRoles().size());
        assertTrue(inDb.getRoles().contains(otherRole));
        assertTrue(!inDb.getRoles().contains(adminRole));

        u.setUsername("CHANGED");
        harness.getUserDAO().updateUser(u);
        inDb = harness.getUserDAO().getUser(u.getId());
        LOG.info("Updated user: {}", inDb);
        assertEquals("CHANGED", inDb.getUsername());

        u.setUsername("TEST");
        harness.getUserDAO().updateUser(u);
    }

    @Test(expected = UnableToExecuteStatementException.class)
    public void updateUser_nameExistsException()
    {
        User u = harness.getUserDAO().findUser("TEST");
        u.setUsername("EXISTS");
        harness.getUserDAO().updateUser(u);
    }


    @Test
    public void testTransaction_withRemnants()
    {
        SupportTransactionTests txUserDAO = harness.getDbi().onDemand(SupportTransactionTests.class);

        // Exception should force rollback
        // commented-out, means: do nothing - hence we expect a User remnant.
        // txUserDAO.throwException = true;

        User u = harness.getUserDAO().findUser("txFOO");
        if (u != null)
        {
            harness.getUserDAO().deleteUser(u.getId());
        }
        Role r = new Role("user", Collections.singleton("bar"));
        u = new User(null, "txFOO", "PASSWORD", Collections.singleton(r));

        Long newId = null;
        try {
            newId = txUserDAO.createUser(u);
        } catch (Exception ignore) {}

        LOG.info("Freshly minted user: {}", u);

        User fromDb = harness.getUserDAO().findUser("txFOO");
       assertEquals(u, fromDb);

        LOG.info("User seen via other DAO: {}", fromDb);
        assertEquals("No roles should have been saved.", 0, fromDb.getRoles().size());

        harness.getUserDAO().deleteUser(newId);

        harness.getDbi().close(txUserDAO);
    }


    @Test
    public void testTransaction_noRemnants()
    {
        SupportTransactionTests txUserDAO = harness.getDbi().onDemand(SupportTransactionTests.class);

        // Exception should force rollback
        txUserDAO.throwException = true;

        User u = harness.getUserDAO().findUser("txFOO");
        if (u != null)
        {
            harness.getUserDAO().deleteUser(u.getId());
        }
        Role r = new Role("user", Collections.singleton("bar"));
        u = new User(null, "txFOO", "PASSWORD", Collections.singleton(r));

        try {
            txUserDAO.createUser(u);
        } catch (Exception ignore) {}

        User fromDb = harness.getUserDAO().findUser("txFOO");
        assertNull("User should not have been persisted.", fromDb);

        harness.getDbi().close(txUserDAO);
    }

}
