package io.ifar.security.realm.model;

import com.google.common.base.Objects;

import java.lang.Override;
import java.lang.String;
import java.sql.Timestamp;
import java.sql.Date;

/**
 * A base class for entities in the model.  Provides common fields and common functionality.
 */
public abstract class BaseEntity {
    protected boolean enabled = true;

    /**
     * This field is intended to be managed by the database.
     */
    protected Timestamp createdAt;

    /**
     * This field is intended to be managed by the database.
     */
    protected Timestamp updatedAt;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public Timestamp getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public String toString() {
        return toStringHelper().toString();
    }

    protected Objects.ToStringHelper toStringHelper() {
        return Objects.toStringHelper(this.getClass().getSimpleName())
                .add("enabled", enabled)
                .add("createdAt", createdAt)
                .add("updatedAt", updatedAt);
    }

}
