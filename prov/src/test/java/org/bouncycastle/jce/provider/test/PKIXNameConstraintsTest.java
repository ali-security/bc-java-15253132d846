package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Test class for {@link PKIXNameConstraintValidator}.
 * <p>
 * The field testXYZ is the name to test.
 * <p>
 * The field testXYZIsConstraint must be tested if it is permitted and excluded.
 * <p>
 * The field testXYZIsNotConstraint must be tested if it is not permitted and
 * not excluded.
 * <p>
 * Furthermore there are tests for the intersection and union of test names.
 * 
 */
public class PKIXNameConstraintsTest
    extends SimpleTest
{

    private final static String testEmail = "test@abc.test.com";

    private final static String testEmailIsConstraint[] =
    { "test@abc.test.com", "abc.test.com", ".test.com" };

    private final static String testEmailIsNotConstraint[] =
    { ".abc.test.com", "www.test.com", "test1@abc.test.com", "bc.test.com" };

    private final static String email1[] =
    { "test@test.com", "test@test.com", "test@test.com", "test@abc.test.com",
            "test@test.com", "test@test.com", ".test.com", ".test.com",
            ".test.com", ".test.com", "test.com", "abc.test.com",
            "abc.test1.com", "test.com", "test.com", ".test.com" };

    private final static String email2[] =
    { "test@test.abc.com", "test@test.com", ".test.com", ".test.com",
            "test.com", "test1.com", "test@test.com", ".test.com",
            ".test1.com", "test.com", "test.com", ".test.com", ".test.com",
            "test1.com", ".test.com", "abc.test.com" };

    private final static String emailintersect[] =
    { null, "test@test.com", null, "test@abc.test.com", "test@test.com", null,
            null, ".test.com", null, null, "test.com", "abc.test.com", null,
            null, null, "abc.test.com" };

    private final static String emailunion[][] =
    {
    { "test@test.com", "test@test.abc.com" },
    { "test@test.com" },
    { "test@test.com", ".test.com" },
    { ".test.com" },
    { "test.com" },
    { "test@test.com", "test1.com" },
    { ".test.com", "test@test.com" },
    { ".test.com" },
    { ".test.com", ".test1.com" },
    { ".test.com", "test.com" },
    { "test.com" },
    { ".test.com" },
    { ".test.com", "abc.test1.com" },
    { "test1.com", "test.com" },
    { ".test.com", "test.com" },
    { ".test.com" } };

    private final static String[] dn1 =
    { "O=test org, OU=test org unit, CN=John Doe" };

    private final static String[] dn2 =
    { "O=test org, OU=test org unit" };

    private final static String[][] dnUnion =
    {
    { "O=test org, OU=test org unit" } };

    private final static String[] dnIntersection =
    { "O=test org, OU=test org unit, CN=John Doe" };

    private final static String testDN = "O=test org, OU=test org unit, CN=John Doe";

    private final static String testDNIsConstraint[] =
    { "O=test org, OU=test org unit",
            "O=test org, OU=test org unit, CN=John Doe" };

    private final static String testDNIsNotConstraint[] =
    { "O=test org, OU=test org unit, CN=John Doe2",
            "O=test org, OU=test org unit2",
            "OU=test org unit, O=test org, CN=John Doe",
            "O=test org, OU=test org unit, CN=John Doe, L=USA" };

    private final static String testDNS = "abc.test.com";

    private final static String testDNSIsConstraint[] =
    { "test.com", "abc.test.com", "test.com" };

    private final static String testDNSIsNotConstraint[] =
    { "wwww.test.com", "ww.test.com", "www.test.com" };

    private final static String dns1[] =
    { "www.test.de", "www.test1.de", "www.test.de" };

    private final static String dns2[] =
    { "test.de", "www.test.de", "www.test.de" };

    private final static String dnsintersect[] =
    { "www.test.de", null, null };

    private final static String dnsunion[][] =
    {
    { "test.de" },
    { "www.test1.de", "www.test.de" },
    { "www.test.de" } };

    private final static String testURI = "http://karsten:password@abc.test.com:8080";

    private final static String testURIIsConstraint[] =
    { "abc.test.com", ".test.com" };

    private final static String testURIIsNotConstraint[] =
    { "xyz.test.com", ".abc.test.com" };

    private final static String uri1[] =
    { "www.test.de", ".test.de", "test1.de", ".test.de" };

    private final static String uri2[] =
    { "test.de", "www.test.de", "test1.de", ".test.de" };

    private final static String uriintersect[] =
    { null, "www.test.de", "test1.de", ".test.de" };

    private final static String uriunion[][] =
    {
    { "www.test.de", "test.de" },
    { ".test.de" },
    { "test1.de" },
    { ".test.de" } };

    private final static byte[] testIP =

    { (byte) 192, (byte) 168, 1, 2 };

    private final static byte[][] testIPIsConstraint =
    {
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 4 } };

    private final static byte[][] testIPIsNotConstraint =
    {
    { (byte) 192, (byte) 168, 3, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 2 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 3 } };

    private final static byte[][] ip1 =
    {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ip2 =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFC, 3 },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF },
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0x00 } };

    private final static byte[][] ipintersect =
    {
            { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFE, (byte) 0xFF },
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF }, null };

    private final static byte[][][] ipunion =
    {
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFE, (byte) 0xFF },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFC, 3 } },
            {
            { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                    (byte) 0xFF, (byte) 0xFF } },
            {
                    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 },
                    { (byte) 192, (byte) 168, 0, 1, (byte) 0xFF, (byte) 0xFF,
                            (byte) 0xFF, (byte) 0x00 } } };

    public String getName()
    {
        return "PKIXNameConstraintsTest";
    }

    public void performTest() throws Exception
    {
        testConstraints(GeneralName.rfc822Name, testEmail,
            testEmailIsConstraint, testEmailIsNotConstraint, email1, email2,
            emailunion, emailintersect);
        testConstraints(GeneralName.dNSName, testDNS, testDNSIsConstraint,
            testDNSIsNotConstraint, dns1, dns2, dnsunion, dnsintersect);
        testConstraints(GeneralName.directoryName, testDN, testDNIsConstraint,
            testDNIsNotConstraint, dn1, dn2, dnUnion, dnIntersection);
        testConstraints(GeneralName.uniformResourceIdentifier, testURI,
            testURIIsConstraint, testURIIsNotConstraint, uri1, uri2, uriunion,
            uriintersect);
        testConstraints(GeneralName.iPAddress, testIP, testIPIsConstraint,
            testIPIsNotConstraint, ip1, ip2, ipunion, ipintersect);
        testNameConstraintBypasses();
    }

    private void testNameConstraintBypasses()
        throws Exception
    {
        // An RFC 1034 root-label trailing dot must not let a host escape an excluded rfc822Name,
        // URI or dNSName subtree.
        checkExcludedTrailingDot(GeneralName.rfc822Name, "bank.com", "ceo@bank.com.");
        checkExcludedTrailingDot(GeneralName.rfc822Name, "ceo@bank.com", "ceo@bank.com.");
        checkExcludedTrailingDot(GeneralName.rfc822Name, ".bank.com", "ceo@mail.bank.com.");
        checkExcludedTrailingDot(GeneralName.uniformResourceIdentifier, "competitor.example", "https://competitor.example./");
        checkExcludedTrailingDot(GeneralName.uniformResourceIdentifier, ".competitor.example", "https://www.competitor.example./");
        checkExcludedTrailingDot(GeneralName.dNSName, "bank.com", "bank.com.");
        checkExcludedTrailingDot(GeneralName.dNSName, "bank.com", "www.bank.com.");

        // an empty label (second trailing dot, doubled dot, leading dot) is refused, not canonicalised
        checkExcludedTrailingDot(GeneralName.rfc822Name, "bank.com", "ceo@bank.com..");
        checkExcludedTrailingDot(GeneralName.uniformResourceIdentifier, "competitor.example", "https://competitor.example../");
        checkExcludedTrailingDot(GeneralName.dNSName, "bank.com", "bank.com..");
        checkExcludedTrailingDot(GeneralName.dNSName, "bank.com", "www..bank.com");
        // a tested mailbox with more than one '@' is ambiguous and refused
        checkExcludedTrailingDot(GeneralName.rfc822Name, "excluded.example.com", "\"user@evil.com\"@excluded.example.com");

        // under a permitted subtree, one trailing dot is accepted and an empty label is refused
        PKIXNameConstraintValidator p = new PKIXNameConstraintValidator();
        p.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")));
        p.checkPermitted(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com."));
        try
        {
            p.checkPermitted(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com.."));
            fail("empty-label host must not be permitted");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }
        org.bouncycastle.asn1.x509.PKIXNameConstraintValidator cp = new org.bouncycastle.asn1.x509.PKIXNameConstraintValidator();
        cp.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")));
        cp.checkPermitted(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com."));
        try
        {
            cp.checkPermitted(new GeneralName(GeneralName.rfc822Name, "ceo@bank.com.."));
            fail("asn1.x509 validator: empty-label host must not be permitted");
        }
        catch (org.bouncycastle.asn1.x509.NameConstraintValidatorException e)
        {
            // expected
        }

        // a host that is not in the excluded subtree is still accepted
        PKIXNameConstraintValidator v = new PKIXNameConstraintValidator();
        v.addExcludedSubtree(new GeneralSubtree(new GeneralName(GeneralName.rfc822Name, "bank.com")));
        v.checkExcluded(new GeneralName(GeneralName.rfc822Name, "ceo@notbank.com."));
    }

    private void checkExcludedTrailingDot(int nameType, String excluded, String name)
        throws Exception
    {
        PKIXNameConstraintValidator v = new PKIXNameConstraintValidator();
        v.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, excluded)));
        try
        {
            v.checkExcluded(new GeneralName(nameType, name));
            fail("trailing-dot name " + name + " must be caught by the excluded " + excluded + " subtree");
        }
        catch (PKIXNameConstraintValidatorException e)
        {
            // expected
        }

        // the public org.bouncycastle.asn1.x509 copy of the validator has the same checks
        org.bouncycastle.asn1.x509.PKIXNameConstraintValidator cv = new org.bouncycastle.asn1.x509.PKIXNameConstraintValidator();
        cv.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, excluded)));
        try
        {
            cv.checkExcluded(new GeneralName(nameType, name));
            fail("asn1.x509 validator: trailing-dot name " + name + " must be caught by the excluded " + excluded + " subtree");
        }
        catch (org.bouncycastle.asn1.x509.NameConstraintValidatorException e)
        {
            // expected
        }
    }

    /**
     * Tests string based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        String testName,
        String[] testNameIsConstraint,
        String[] testNameIsNotConstraint,
        String[] testNames1,
        String[] testNames2,
        String[][] testUnion,
        String[] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNameIsConstraint[i])));
            constraintValidator.checkPermitted(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNameIsNotConstraint[i])));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType, testName));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsConstraint[i])));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType, testName));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNameIsNotConstraint[i])));
            constraintValidator.checkExcluded(new GeneralName(nameType, testName));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames1[i])));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, testNames2[i])));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testUnion[i][j])));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNames1[i])));
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, testNames2[i])));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, testInterSection[i])));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    /**
     * Tests byte array based GeneralNames for inclusion or exclusion.
     * 
     * @param nameType The {@link GeneralName} type to test.
     * @param testName The name to test.
     * @param testNameIsConstraint The names where <code>testName</code> must
     *            be included and excluded.
     * @param testNameIsNotConstraint The names where <code>testName</code>
     *            must not be excluded and included.
     * @param testNames1 Operand 1 of test names to use for union and
     *            intersection testing.
     * @param testNames2 Operand 2 of test names to use for union and
     *            intersection testing.
     * @param testUnion The union results.
     * @param testInterSection The intersection results.
     * @throws Exception If an unexpected exception occurs.
     */
    private void testConstraints(
        int nameType,
        byte[] testName,
        byte[][] testNameIsConstraint,
        byte[][] testNameIsNotConstraint,
        byte[][] testNames1,
        byte[][] testNames2,
        byte[][][] testUnion,
        byte[][] testInterSection) throws Exception
    {
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsConstraint[i]))));
            constraintValidator.checkPermitted(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testNameIsNotConstraint[i]))));
            try
            {
                constraintValidator.checkPermitted(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("not permitted name allowed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsConstraint[i]))));
            try
            {
                constraintValidator.checkExcluded(new GeneralName(nameType,
                    new DEROctetString(testName)));
                fail("excluded name missed: " + nameType);
            }
            catch (PKIXNameConstraintValidatorException e)
            {
                // expected
            }
        }
        for (int i = 0; i < testNameIsNotConstraint.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNameIsNotConstraint[i]))));
            constraintValidator.checkExcluded(new GeneralName(nameType,
                new DEROctetString(testName)));
        }
        for (int i = 0; i < testNames1.length; i++)
        {
            PKIXNameConstraintValidator constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.addExcludedSubtree(new GeneralSubtree(new GeneralName(
                nameType, new DEROctetString(testNames2[i]))));
            PKIXNameConstraintValidator constraints2 = new PKIXNameConstraintValidator();
            for (int j = 0; j < testUnion[i].length; j++)
            {
                constraints2.addExcludedSubtree(new GeneralSubtree(
                    new GeneralName(nameType, new DEROctetString(
                        testUnion[i][j]))));
            }
            if (!constraints2.equals(constraintValidator))
            {
                fail("union wrong: " + nameType);
            }
            constraintValidator = new PKIXNameConstraintValidator();
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames1[i]))));
            constraintValidator.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(testNames2[i]))));
            constraints2 = new PKIXNameConstraintValidator();
            if (testInterSection[i] != null)
            {
                constraints2.intersectPermittedSubtree(new GeneralSubtree(
                new GeneralName(nameType, new DEROctetString(
                    testInterSection[i]))));
            }
            else
            {
                constraints2.intersectEmptyPermittedSubtree(nameType);
            }

            if (!constraints2.equals(constraintValidator))
            {
                fail("intersection wrong: " + nameType);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new PKIXNameConstraintsTest());
    }
}
