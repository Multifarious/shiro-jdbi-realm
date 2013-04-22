package io.ifar.security.dao.jdbi;


/**
 * Used to support testing that transaction boundaries are being enforced.
 */
public abstract class SupportTransactionTests extends DefaultJdbiUserDAO {

    // either throw an exception or do nothing at all.
    boolean throwException = false;

    /**
     * Either throw an Exception or do nothing.
     */
    protected void createUserRole(Long userId, String roleName)
    {
        if (throwException)
        {
            throw new RuntimeException("TEST - transaction should be rolled back... no remnants.");
        }

    }

}
