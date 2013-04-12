package io.ifar.security.realm.model;

import com.google.common.base.Objects;

import java.util.HashSet;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * This class represents a Role that can be assigned to a {@link User}.
 */
public class Role {
    private final String name;
    private final Set<String> permissions;

    public Role(String name) {
        this(name, null);
    }

    public Role(String name, Set<String> permissions)
    {
        checkArgument(name != null, "A Role's name cannot be null.");
        this.name = name;
        this.permissions = (permissions != null ? permissions : new HashSet<String>());
    }

    public String getName() {
        return name;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    /**
     * Instance equality based on the value of the name and permissions fields.
     * <p>
     *     Note that, as a consequence, unlike the default Java implementation, two instances of this
     *     class (or subclasses) are equal if their contents are equal.  In particular this means that you cannot
     *     add more than one uninitialized instance to some collections (for example, to a Set).
     * </p>
     * Allow subclasses since some persistence frameworks wrap the POJOs behind the scenes.
     * Allow nulls even for not-null columns so instances can be compared before they are persisted.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Role)) return false;

        Role role = (Role) o;
        return (name.equals(role.name)) && (permissions.equals(role.permissions));
    }

    @Override
    public int hashCode() {
        int result = name.hashCode();
        result = 31 * result + permissions.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this.getClass().getSimpleName() + '[' + System.identityHashCode(this) + ']')
                .add("name", name)
                .add("permissions", permissions)
                .toString();
    }

}
