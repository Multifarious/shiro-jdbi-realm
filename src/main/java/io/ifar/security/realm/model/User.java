package io.ifar.security.realm.model;

import com.google.common.base.Objects;

import java.util.HashSet;
import java.util.Set;

/**
 * This class represents a User of the system.  In the context of security, the user is mapped to a "subject."
 *
 * @see org.apache.shiro.subject.Subject
 */
public class User {

    private Long id;
    private String username;
    private String password;
    private Set<Role> roles = new HashSet<>();

    public User()
    {
    }

    public User(Long id, String username, String password, Set<Role> roles)
    {
        this.id = id;
        this.username = username;
        this.password = password;
        this.roles = (roles != null ? roles : new HashSet<Role>());
    }

    public Long getId() {
        return id;
    }

    /**
     * Sets the User's id.  The id is a required field.
     * Normally this is assigned by the backing database.
     *
     * @param id User's assigned primary key identifier
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Returns the username associated with this user account.
     *
     * @return the username associated with this user account.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets this user account's username.
     * The username must be set before the record is persisted.
     *
     * @param username unique and not-null
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Returns the hashed password for this user.
     * <p>
     *     If the password is salted (and it should be) the salt is stored in the password.
     *     See, for example {@link org.apache.shiro.crypto.hash.format.ParsableHashFormat} and, in particular,
     *     {@link org.apache.shiro.crypto.hash.format.Shiro1CryptFormat}.
     * </p>
     *
     * @return this user's password
     */
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }


    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    /**
     * Instance equality based on the value of the id and username fields.
     * <p>
     *     Note that, as a consequence, unlike the default Java implementation, two instances of this
     *     class (or subclasses) are equal if their contents are equal.  In particular this means that you cannot
     *     add more than one uninitialized instance to some collections (for example, to a Set).
     * </p>
     *
     * Allow subclasses since some persistence frameworks wrap the POJOs behind the scenes.
     * Allow nulls even for not-null columns so instances can be compared before they are persisted.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;

        User user = (User) o;
        return Objects.equal(id, user.id) && Objects.equal(username, user.username);
    }

    @Override
    public int hashCode() {
        int result = id != null ? id.hashCode() : 0;
        result = 31 * result + (username != null ? username.hashCode() : 0);
        return result;
    }

    /**
     * Don't show value of password fields.
     */
    @Override
    public String toString() {
        return Objects.toStringHelper(this.getClass().getSimpleName() + '[' + System.identityHashCode(this) + ']')
                .add("id", id)
                .add("username", username)
                .add("password", "********")
                .add("roles", roles)
                .toString();
    }

}
