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
