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

    /**
     * Upper bound on the PBKDF2 iteration count honoured by the raw JCA PBKDF2 provider (both the
     * SecretKeyFactory derivation and the AlgorithmParameters parse a Cipher performs for PBES2).
     * The count can travel inside an unauthenticated container, so an unbounded count is a
     * CPU-exhaustion vector. Default 10,000,000. Read via {@link #asInteger(String, int)}.
     */
    public static final String PBE_MAX_ITERATION_COUNT = "org.bouncycastle.pbe.max_iteration_count";

    /**
     * Opt in to handling legacy version 0/1 BKS keystores. Those stores derive the HMAC integrity
     * key at only the digest size in bits (a 16-bit key for SHA-1), which is brute-forceable
     * offline, so by default the default BKS keystore type refuses to load them. Set this property
     * to read or create the weak legacy format (e.g. to migrate an old store); it also gates
     * registration of the separate BKS-V1 keystore type. Read via {@link #isOverrideSet(String)}.
     */
    public static final String BKS_ENABLE_V1 = "org.bouncycastle.bks.enable_v1";

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
