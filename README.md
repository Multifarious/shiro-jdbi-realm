# io.ifar: shiro-jdbi-realm

JdbiRealm for Shiro.

Database-backed UserDAO-based Shiro Realm with database access implemented via DBI.

Designed for use with Dropwizard.

## Functionality

The bundle includes all the pieces needed for a simple database-backed Realm that can be used to authenticate and authorize users.


## Usage / Configuration

Include [the maven dependency](#access-with-maven).

You need to configure database access.  For example, via a DatabaseConfiguration section of your `.yml` config file.

Add a `JdbiRealmLoaderListener` that will inject a DBI instance into the JdbiShiroRealm instances.

    import com.yammer.dropwizard.Service;
    import com.yammer.dropwizard.config.Environment;
    import com.yammer.dropwizard.jdbi.DBIFactory;
    import io.ifar.security.web.JdbiRealmLoaderListener;
    import org.apache.shiro.web.env.EnvironmentLoaderListener;
    import org.apache.shiro.web.servlet.ShiroFilter;
    import org.eclipse.jetty.server.session.SessionHandler;
    import org.skife.jdbi.v2.DBI;
    ...
    public class ExampleService extends Service<ExampleConfiguration> {
    ...
        @Override
        public void run(ExampleConfiguration config,
                        Environment environment) throws ClassNotFoundException {

            // setup Shiro
            environment.setSessionHandler(new SessionHandler());
            environment.addServletListeners(new EnvironmentLoaderListener());
            environment.addFilter(new ShiroFilter(), "/*").setName("shiro-filter");

            // create a DBI
            final DBIFactory factory = new DBIFactory();
            final DBI jdbi = factory.build(environment, config.getDatabaseConfiguration(), "hsqldb");

            // make sure each JdbiRealm has the DBI.
            environment.addServletListeners(new JdbiRealmLoaderListener(jdbi));
            ...
        }
    ...
    }

Alternatively, if using an IOC container like Spring or Guice you can do the full configuration of the JdbiShiroRealm via those frameworks.

### Database

The database needs to exist and have the expected tables.  See the changelogs in the ./src/main/resources/liquibase folder.

Classes in this package can be used for creating Users and assigning them Roles.  Currently Roles and Permissions need to be pre-configured, e.g., via SQL.

### Related Shiro and Dropwizard Configuration

The JdbiShiroRealm instance can be created and assignd to the securityManager via the Shiro `.ini`

    [main]
    ...
    # Users, roles, and permissions from the database, accessed via DBI.
    jdbiRealm = io.ifar.security.realm.JdbiShiroRealm
    securityManager.realm = $jdbiRealm
    ...

You can optionally set the `jdbiRealm.credentialsMatcher` and other inherited properties on the realm instance such as the AuthorizingRealm's `authorizationCache`.

## Access with Maven

### Coordinates

Include the following in your `pom.xml`:

	<dependency>
	  <groupId>io.ifar</groupId>
	  <artifactId>shiro-jdbi-realm</artifactId>
	  <version>0.0.1-SNAPSHOT</version>
	</dependency>

### Snapshots

Snapshots are available from the following Maven repository:


    <repository>
      <id>multifarious-snapshots</id>
      <name>Multifarious, Inc. Snapshot Repository</name>
      <url>http://repository-multifarious.forge.cloudbees.com/snapshot/</url>
      <snapshots>
        <enabled>true</enabled>
      </snapshots>
      <releases>
        <enabled>false</enabled>
      </releases>
    </repository>


### Releases

None as yet, but when there are, they will be published via Maven Central.

## License

The license is [BSD 2-clause](http://opensource.org/licenses/BSD-2-Clause).  This information is also present in the `LICENSE.txt` file and in the `pom.xml`.