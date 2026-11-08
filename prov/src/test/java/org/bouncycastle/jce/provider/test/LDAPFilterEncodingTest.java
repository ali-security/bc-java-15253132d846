package org.bouncycastle.jce.provider.test;

import java.lang.reflect.Method;

import org.bouncycastle.jce.X509LDAPCertStoreParameters;
import org.bouncycastle.jce.provider.X509LDAPCertStoreSpi;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.util.LDAPStoreHelper;

/**
 * The values both LDAP classes take from an X.500 name must be RFC 2254 escaped before they go into a
 * search filter (CVE-2023-33201 for X509LDAPCertStoreSpi, CVE-2026-0636 for LDAPStoreHelper).
 */
public class LDAPFilterEncodingTest
    extends SimpleTest
{
    public String getName()
    {
        return "LDAPFilterEncoding";
    }

    private static String parseDN(Object target, String subject, String attributeName)
        throws Exception
    {
        Method m = target.getClass().getDeclaredMethod("parseDN", new Class[]{String.class, String.class});
        m.setAccessible(true);
        return (String)m.invoke(target, new Object[]{subject, attributeName});
    }

    private void checkParse(Object target, String label, String expected, String subject)
        throws Exception
    {
        String actual = parseDN(target, subject, "cn");
        if (!expected.equals(actual))
        {
            fail(target.getClass().getName() + ": " + label + ": expected " + expected + " got " + actual);
        }
    }

    private void checkEncoding(Object target)
        throws Exception
    {
        checkParse(target, "wildcard injection", "\\29\\28cn=", "CN=\")(cn=\"");
        checkParse(target, "all special characters", "a\\2ab\\28c\\29d\\5ce", "CN=\"a*b(c)d\\e\", O=x");
        checkParse(target, "plain value unchanged", "Test User", "CN=Test User, O=Example");
    }

    public void performTest()
        throws Exception
    {
        X509LDAPCertStoreParameters params = new X509LDAPCertStoreParameters.Builder("ldap://127.0.0.1:1", "dc=example").build();

        checkEncoding(new X509LDAPCertStoreSpi(params));
        checkEncoding(new LDAPStoreHelper(params));
    }

    public static void main(String[] args)
    {
        runTest(new LDAPFilterEncodingTest());
    }
}
