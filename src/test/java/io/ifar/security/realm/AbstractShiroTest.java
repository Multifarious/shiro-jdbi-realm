package io.ifar.security.realm;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.*;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.SubjectThreadState;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.util.ThreadState;
import org.junit.After;
import org.junit.Before;

/**
 * Project: security
 * User: ezra
 * Date: 4/3/13
 */
public abstract class AbstractShiroTest {

    protected static ThreadState subjectThreadState;
    protected static DefaultPasswordService passwordService; // = new DefaultPasswordService();   NOW from .ini
    protected static CredentialsMatcher passwordMatcher;

    protected static void setupShiro() {
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(); // ("classpath:shiro.ini");
        DefaultSecurityManager dsm = (DefaultSecurityManager) factory.getInstance();
        passwordService = (DefaultPasswordService) factory.getBeans().get("passwordService");
        passwordMatcher = (CredentialsMatcher) factory.getBeans().get("passwordMatcher");
        setSecurityManager(dsm);
    }

    protected static void tearDownShiro() {
        doClearSubject();
        try {
            SecurityManager securityManager = getSecurityManager();
            LifecycleUtils.destroy(securityManager);
        } catch (UnavailableSecurityManagerException e) {
            //we don't care about this when cleaning up the test environment
        }
        setSecurityManager(null);
    }

    protected static void doClearSubject() {
        if (subjectThreadState != null) {
            subjectThreadState.clear();
            subjectThreadState = null;
        }
    }

    protected static void setSecurityManager(DefaultSecurityManager securityManager) {
        SecurityUtils.setSecurityManager(securityManager);
    }

    protected static DefaultSecurityManager getSecurityManager() {
        return (DefaultSecurityManager) SecurityUtils.getSecurityManager();
    }

    @Before
    public void preTestBase() {
        setSubject(new Subject.Builder(getSecurityManager()).buildSubject());
    }

    @After
    public void postTestBase() {
        clearSubject();
    }

    /**
     * Clears Shiro's thread state, ensuring the thread remains clean for future test execution.
     */
    protected void clearSubject() {
        doClearSubject();
    }

    protected void setSubject(Subject subject) {
        clearSubject();
        subjectThreadState = createThreadState(subject);
        subjectThreadState.bind();
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    protected ThreadState createThreadState(Subject subject) {
        return new SubjectThreadState(subject);
    }

}
