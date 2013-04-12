# io.ifar: shiro-jdbi-realm

JdbiRealm for Shiro.

Database-backed UserDAO-based Shiro Realm with database access implemented via DBI.

Designed for use with Dropwizard.

## Functionality

The bundle includes all the pieces needed for a simple database-backed Realm that can be used to authenticate and authorize users.


## Usage

Include [the maven dependency](#access-with-maven).

TBC.

## Configuration

PENDING

### Related Shiro and Dropwizard Configuration

PENDING


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