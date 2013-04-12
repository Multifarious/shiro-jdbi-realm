package io.ifar.security.dao.jdbi;

import liquibase.Liquibase;
import liquibase.database.jvm.HsqlConnection;
import liquibase.logging.LogFactory;
import liquibase.resource.FileSystemResourceAccessor;
import liquibase.resource.ResourceAccessor;
import org.apache.shiro.io.ResourceUtils;
import org.skife.jdbi.v2.DBI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

/**
 * Project: security
 * User: ezra
 * Date: 3/26/13
 */
public class DatabaseUtils {

    private static final Logger LOG = LoggerFactory.getLogger(DatabaseUtils.class);

    protected static final String DB_PROPERTIES_FILE_PATH = "classpath:test.db.properties";

    protected static final String DB_DRIVER_CLASSNAME_KEY = "jdbc.driver.className";
    protected static final String DB_CONNECTION_URL_KEY = "jdbc.connection.url";
    protected static final String DB_CONNECTION_USERNAME_KEY = "jdbc.connection.username";
    protected static final String DB_CONNECTION_PASSWORD_KEY = "jdbc.connection.password";

    // DEFAULT value - used value can be overridden by setting the jdbc.driver.className in the test.db.properties file.
    private static final String JDBC_DRIVER_CLASSNAME = "org.hsqldb.jdbcDriver";
    // DEFAULT value - value can be overridden by setting the jdbc.connection.url in the test.db.properties file.
    private static final String JDBC_CONNECTION_STRING = "jdbc:hsqldb:mem:testdb;shutdown=false";
    // DEFAULT value - value can be overridden by setting the jdbc.connection.username in the test.db.properties file.
    private static final String DB_USER_NAME = "sa";
    private static final String DB_PASSWORD = "";

    private static final String CHANGE_LOG = "src/main/resources/liquibase/master.xml";
    private static final String TEST_DATA_CHANGE_LOG = "src/test/resources/liquibase/test_changeset_2-5.sql";

    protected Properties dbProperties = null;
    protected DBI dbi;
    protected DefaultJDBIUserDAO userDAO;

    private void loadProperties(String resourcePath) {
        InputStream propStream = null;
        try {
            propStream = ResourceUtils.getInputStreamForPath(resourcePath);
        } catch (IOException iox) {
            LOG.info("No properties file found at {}, using default values.", resourcePath);
        }

        if (propStream != null) {
            dbProperties = new Properties();
            try {
                dbProperties.load(propStream);
            } catch (IOException iox) {
                LOG.error("Error loading properties from: " + resourcePath);
                throw new RuntimeException(iox);
            }
        }
    }

    public String getJdbcDriverClassname()
    {
        return (dbProperties != null && dbProperties.containsKey(DB_DRIVER_CLASSNAME_KEY)) ?
                dbProperties.getProperty(DB_DRIVER_CLASSNAME_KEY) : JDBC_DRIVER_CLASSNAME;
    }

    public String getJdbcConnectionString()
    {
        return (dbProperties != null && dbProperties.containsKey(DB_CONNECTION_URL_KEY)) ?
                dbProperties.getProperty(DB_CONNECTION_URL_KEY) : JDBC_CONNECTION_STRING;
    }

    public String getDbUsername()
    {
        return (dbProperties != null && dbProperties.containsKey(DB_CONNECTION_USERNAME_KEY)) ?
                dbProperties.getProperty(DB_CONNECTION_USERNAME_KEY) : DB_USER_NAME;
    }

    public String getDbPassword()
    {
        return (dbProperties != null && dbProperties.containsKey(DB_CONNECTION_PASSWORD_KEY)) ?
                dbProperties.getProperty(DB_CONNECTION_PASSWORD_KEY) : DB_PASSWORD;
    }

    private void performDatabaseSetupOrClean(boolean setup) {
        try {
            ResourceAccessor resourceAccessor = new FileSystemResourceAccessor();
            Class.forName(getJdbcDriverClassname());

            Connection holdingConnection = DriverManager.getConnection(getJdbcConnectionString(), getDbUsername(), getDbPassword());
            HsqlConnection hsconn = new HsqlConnection(holdingConnection);
            LogFactory.getLogger().setLogLevel("warning");
            Liquibase liquibase = new Liquibase(CHANGE_LOG, resourceAccessor, hsconn);
            liquibase.dropAll();
            if (setup) {
                liquibase.update("test");

                liquibase = new Liquibase(TEST_DATA_CHANGE_LOG, resourceAccessor, hsconn);
                liquibase.update("test");
            }

            hsconn.close();
        } catch (Exception ex) {
            String msg = setup ? "Error during database initialization" : "Error during database clean-up";
            LOG.error(msg, ex);
            throw new RuntimeException(msg, ex);
        }
    }

    public void setUp() {
        loadProperties(DB_PROPERTIES_FILE_PATH);

        performDatabaseSetupOrClean(true);

        dbi = new DBI(getJdbcConnectionString(), getDbUsername(), getDbPassword());
        userDAO = dbi.onDemand(DefaultJDBIUserDAO.class);
    }

    /**
     * Play nice with other test classes
     */
    public void tearDown()
    {
        if (dbProperties == null)
        {
            loadProperties(DB_PROPERTIES_FILE_PATH);
        }
        performDatabaseSetupOrClean(false);
        dbi.close(userDAO);
    }

    public DBI getDbi() {
        return dbi;
    }

    public DefaultJDBIUserDAO getUserDAO() {
        return userDAO;
    }
}
