package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Utility method for accessing system properties.
 */
public class Properties
{
    /**
     * Upper bound on the PBKDF2 iteration count honoured when deriving the integrity-MAC key of a
     * BCFKS keystore during load. Default 5,000,000. Read via {@link #asInteger(String, int)}.
     */
    public static final String BCFKS_MAX_IT_COUNT = "org.bouncycastle.bcfks.max_it_count";

    public static boolean isOverrideSet(final String propertyName)
    {
        try
        {
            return "true".equals(AccessController.doPrivileged(new PrivilegedAction()
            {
                // JDK 1.4 compatibility
                public Object run()
                {
                    String value = System.getProperty(propertyName);
                    if (value == null)
                    {
                        return null;
                    }

                    return Strings.toLowerCase(value);
                }
            }));
        }
        catch (AccessControlException e)
        {
            return false;
        }
    }

    /**
     * Return propertyName as a BigInteger, or null if the property is not set or not readable.
     */
    public static BigInteger asBigInteger(final String propertyName)
    {
        String value = getPropertyValue(propertyName);
        if (value == null)
        {
            return null;
        }

        return new BigInteger(value.trim());
    }

    /**
     * Return propertyName as an int, or defaultValue if the property is not set or not readable.
     */
    public static int asInteger(String propertyName, int defaultValue)
    {
        String value = getPropertyValue(propertyName);
        if (value == null)
        {
            return defaultValue;
        }

        return Integer.parseInt(value.trim());
    }

    private static String getPropertyValue(final String propertyName)
    {
        try
        {
            return (String)AccessController.doPrivileged(new PrivilegedAction()
            {
                // JDK 1.4 compatibility
                public Object run()
                {
                    return System.getProperty(propertyName);
                }
            });
        }
        catch (AccessControlException e)
        {
            return null;
        }
    }
}
