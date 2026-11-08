package org.bouncycastle.crypto.tls.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsRSAUtils;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.util.Arrays;

/**
 * Tests for the RSA-encrypted premaster secret decryption used by TLS servers (CVE-2024-30171).
 * <p>
 * Decryption must use implicit rejection: whatever the ciphertext, no exception is raised and a 48 byte
 * premaster secret is returned. If the PKCS#1 v1.5 encoding or the embedded version number is invalid,
 * that value is random, so a server can't be used as a padding oracle.
 * </p>
 */
public class TlsRSAUtilsTest
    extends TestCase
{
    private static final int TLS12 = 0x0303;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static AsymmetricCipherKeyPair kp1024;
    private static AsymmetricCipherKeyPair kp1028;

    private static synchronized AsymmetricCipherKeyPair getKeyPair(int bits)
    {
        if (bits == 1024)
        {
            if (kp1024 == null)
            {
                kp1024 = generateKeyPair(1024);
            }
            return kp1024;
        }
        if (kp1028 == null)
        {
            kp1028 = generateKeyPair(1028);
        }
        return kp1028;
    }

    private static AsymmetricCipherKeyPair generateKeyPair(int bits)
    {
        RSAKeyPairGenerator kpGen = new RSAKeyPairGenerator();

        kpGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), RANDOM, bits, 25));

        return kpGen.generateKeyPair();
    }

    private static byte[] createPreMasterSecret(int version)
    {
        byte[] pms = new byte[48];
        RANDOM.nextBytes(pms);
        pms[0] = (byte)(version >>> 8);
        pms[1] = (byte)version;
        return pms;
    }

    /**
     * Build a PKCS#1 v1.5 type 2 block of the full modulus length: 0x00 || 0x02 || PS || 0x00 || M.
     */
    private static byte[] createType2Block(RSAKeyParameters key, byte[] message)
    {
        int k = (key.getModulus().bitLength() + 7) / 8;
        int padLen = k - 3 - message.length;

        byte[] block = new byte[k];
        block[0] = 0x00;
        block[1] = 0x02;
        for (int i = 0; i != padLen; i++)
        {
            block[2 + i] = (byte)(0x11 + (i % 0xe0));       // non-zero padding
        }
        block[2 + padLen] = 0x00;
        System.arraycopy(message, 0, block, 3 + padLen, message.length);
        return block;
    }

    private static byte[] rawEncrypt(RSAKeyParameters pubKey, byte[] block)
    {
        AsymmetricBlockCipher eng = new RSAEngine();
        eng.init(true, pubKey);
        try
        {
            return eng.processBlock(block, 0, block.length);
        }
        catch (InvalidCipherTextException e)
        {
            throw new IllegalStateException("raw RSA encryption failed: " + e.getMessage());
        }
    }

    private static byte[] pkcs1Encrypt(RSAKeyParameters pubKey, byte[] message)
        throws Exception
    {
        AsymmetricBlockCipher eng = new PKCS1Encoding(new RSAEngine());
        eng.init(true, new ParametersWithRandom(pubKey, RANDOM));
        return eng.processBlock(message, 0, message.length);
    }

    private static RSAKeyParameters withoutCrt(RSAKeyParameters privKey)
    {
        return new RSAKeyParameters(true, privKey.getModulus(), privKey.getExponent());
    }

    private static TlsContext createServerContext(final ProtocolVersion clientVersion, final SecureRandom random)
    {
        return new TlsContext()
        {
            private Object userObject;

            public RandomGenerator getNonceRandomGenerator()
            {
                return null;
            }

            public SecureRandom getSecureRandom()
            {
                return random;
            }

            public SecurityParameters getSecurityParameters()
            {
                return null;
            }

            public boolean isServer()
            {
                return true;
            }

            public ProtocolVersion getClientVersion()
            {
                return clientVersion;
            }

            public ProtocolVersion getServerVersion()
            {
                return clientVersion;
            }

            public TlsSession getResumableSession()
            {
                return null;
            }

            public Object getUserObject()
            {
                return userObject;
            }

            public void setUserObject(Object userObject)
            {
                this.userObject = userObject;
            }

            public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length)
            {
                throw new UnsupportedOperationException();
            }
        };
    }

    public void testValidPreMasterSecret()
        throws Exception
    {
        checkValidPreMasterSecret(1024);
        checkValidPreMasterSecret(1028);
    }

    private void checkValidPreMasterSecret(int bits)
        throws Exception
    {
        AsymmetricCipherKeyPair kp = getKeyPair(bits);
        RSAKeyParameters pubKey = (RSAKeyParameters)kp.getPublic();
        RSAPrivateCrtKeyParameters privKey = (RSAPrivateCrtKeyParameters)kp.getPrivate();
        TlsContext context = createServerContext(ProtocolVersion.TLSv12, RANDOM);

        for (int i = 0; i < 20; ++i)
        {
            byte[] pms = createPreMasterSecret(TLS12);
            byte[] encrypted = pkcs1Encrypt(pubKey, pms);

            assertTrue(Arrays.areEqual(pms, TlsRSAUtils.decryptPreMasterSecret(encrypted, privKey, TLS12, RANDOM)));
            assertTrue(Arrays.areEqual(pms, TlsRSAUtils.decryptPreMasterSecret(encrypted, withoutCrt(privKey), TLS12, RANDOM)));
            assertTrue(Arrays.areEqual(pms, TlsRSAUtils.decryptPreMasterSecret(encrypted, privKey, TLS12, null)));
            assertTrue(Arrays.areEqual(pms, TlsRSAUtils.safeDecryptPreMasterSecret(context, privKey, encrypted)));
        }

        // a ciphertext without its leading zero bytes is still accepted
        byte[] pms = createPreMasterSecret(TLS12);
        byte[] encrypted = rawEncrypt(pubKey, createType2Block(pubKey, pms));
        int zeros = 0;
        while (encrypted[zeros] == 0)
        {
            ++zeros;
        }
        byte[] stripped = Arrays.copyOfRange(encrypted, zeros, encrypted.length);
        assertTrue(Arrays.areEqual(pms, TlsRSAUtils.decryptPreMasterSecret(stripped, privKey, TLS12, RANDOM)));
    }

    public void testVersionMismatchIsImplicitlyRejected()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = getKeyPair(1024);
        RSAKeyParameters pubKey = (RSAKeyParameters)kp.getPublic();
        RSAKeyParameters privKey = (RSAKeyParameters)kp.getPrivate();

        int[] wrongVersions = new int[]{ 0x0300, 0x0301, 0x0302, 0x0203, 0x0403, 0x0000, 0xFFFF };
        for (int i = 0; i < wrongVersions.length; ++i)
        {
            byte[] pms = createPreMasterSecret(wrongVersions[i]);
            byte[] encrypted = pkcs1Encrypt(pubKey, pms);

            checkImplicitRejection("version " + Integer.toHexString(wrongVersions[i]), encrypted, privKey, pms);
        }

        // the version check uses the client version from the context
        byte[] pms = createPreMasterSecret(ProtocolVersion.TLSv11.getFullVersion());
        byte[] encrypted = pkcs1Encrypt(pubKey, pms);

        assertTrue(Arrays.areEqual(pms,
            TlsRSAUtils.safeDecryptPreMasterSecret(createServerContext(ProtocolVersion.TLSv11, RANDOM), privKey, encrypted)));
        byte[] result = TlsRSAUtils.safeDecryptPreMasterSecret(createServerContext(ProtocolVersion.TLSv12, RANDOM), privKey, encrypted);
        assertEquals(48, result.length);
        assertFalse(Arrays.areEqual(pms, result));
    }

    /*
     * The ciphertexts an attacker submits when using the server as a Bleichenbacher/Marvin padding oracle:
     * none of them may produce an exception or reveal the decrypted data.
     */
    public void testMalformedEncodingsAreImplicitlyRejected()
        throws Exception
    {
        checkMalformedEncodings(1024);
        checkMalformedEncodings(1028);
    }

    private void checkMalformedEncodings(int bits)
        throws Exception
    {
        AsymmetricCipherKeyPair kp = getKeyPair(bits);
        RSAKeyParameters pubKey = (RSAKeyParameters)kp.getPublic();
        RSAKeyParameters privKey = (RSAKeyParameters)kp.getPrivate();
        int k = (pubKey.getModulus().bitLength() + 7) / 8;

        byte[] pms = createPreMasterSecret(TLS12);
        byte[] good = createType2Block(pubKey, pms);
        int separator = k - 1 - pms.length;

        assertTrue(Arrays.areEqual(pms, TlsRSAUtils.decryptPreMasterSecret(rawEncrypt(pubKey, good), privKey, TLS12, RANDOM)));

        // wrong block type
        byte[] block = Arrays.clone(good);
        block[1] = 0x01;
        checkImplicitRejection("block type 1", rawEncrypt(pubKey, block), privKey, pms);

        block = Arrays.clone(good);
        block[1] = 0x00;
        checkImplicitRejection("block type 0", rawEncrypt(pubKey, block), privKey, pms);

        // non-zero leading byte
        block = Arrays.clone(good);
        block[0] = 0x01;
        if (new BigInteger(1, block).compareTo(pubKey.getModulus()) < 0)
        {
            checkImplicitRejection("non-zero leading byte", rawEncrypt(pubKey, block), privKey, pms);
        }

        // zero byte inside the padding string
        block = Arrays.clone(good);
        block[2 + (separator - 2) / 2] = 0x00;
        checkImplicitRejection("zero byte in padding", rawEncrypt(pubKey, block), privKey, pms);

        // zero byte as the first padding byte
        block = Arrays.clone(good);
        block[2] = 0x00;
        checkImplicitRejection("zero first padding byte", rawEncrypt(pubKey, block), privKey, pms);

        // missing zero separator
        block = Arrays.clone(good);
        block[separator] = 0x5a;
        checkImplicitRejection("missing separator", rawEncrypt(pubKey, block), privKey, pms);

        // premaster secret too short (47 bytes)
        byte[] shortPms = Arrays.copyOfRange(pms, 0, 47);
        block = createType2Block(pubKey, shortPms);
        checkImplicitRejection("47 byte premaster secret", rawEncrypt(pubKey, block), privKey,
            Arrays.copyOfRange(block, k - 48, k));

        // premaster secret too long (49 bytes)
        byte[] longPms = Arrays.concatenate(new byte[]{ 0x03 }, createPreMasterSecret(TLS12));
        block = createType2Block(pubKey, longPms);
        checkImplicitRejection("49 byte premaster secret", rawEncrypt(pubKey, block), privKey,
            Arrays.copyOfRange(block, k - 48, k));

        // all-zero padding string, with the version in place
        block = Arrays.clone(good);
        for (int i = 2; i < separator; ++i)
        {
            block[i] = 0x00;
        }
        checkImplicitRejection("zero padding string", rawEncrypt(pubKey, block), privKey, pms);

        // ciphertext equal to the modulus, or larger
        byte[] modulus = toUnsigned(pubKey.getModulus());
        checkImplicitRejection("ciphertext == modulus", modulus, privKey, pms);
        checkImplicitRejection("ciphertext > modulus", toUnsigned(pubKey.getModulus().add(BigInteger.valueOf(1))), privKey, pms);

        // ciphertext longer than the modulus
        checkImplicitRejection("ciphertext too long", Arrays.concatenate(new byte[1], rawEncrypt(pubKey, good), new byte[1]), privKey, pms);

        // random ciphertexts
        for (int i = 0; i < 50; ++i)
        {
            byte[] encrypted = new byte[k];
            RANDOM.nextBytes(encrypted);
            encrypted[0] = 0;
            checkImplicitRejection("random ciphertext", encrypted, privKey, null);
        }
    }

    public void testInvalidArguments()
        throws Exception
    {
        AsymmetricCipherKeyPair kp = getKeyPair(1024);
        RSAKeyParameters pubKey = (RSAKeyParameters)kp.getPublic();
        RSAKeyParameters privKey = (RSAKeyParameters)kp.getPrivate();
        byte[] encrypted = pkcs1Encrypt(pubKey, createPreMasterSecret(TLS12));

        checkIllegalArgument(null, privKey, TLS12);
        checkIllegalArgument(new byte[0], privKey, TLS12);
        checkIllegalArgument(encrypted, pubKey, TLS12);
        checkIllegalArgument(encrypted, privKey, 0x10000);
        checkIllegalArgument(encrypted, privKey, -1);

        RSAKeyParameters smallKey = (RSAKeyParameters)generateKeyPair(384).getPrivate();
        checkIllegalArgument(encrypted, smallKey, TLS12);

        // the TLS server entry point never throws: it falls back to a random premaster secret
        TlsContext context = createServerContext(ProtocolVersion.TLSv12, RANDOM);
        byte[] r1 = TlsRSAUtils.safeDecryptPreMasterSecret(context, privKey, new byte[0]);
        byte[] r2 = TlsRSAUtils.safeDecryptPreMasterSecret(context, smallKey, encrypted);
        assertEquals(48, r1.length);
        assertEquals(48, r2.length);
        assertFalse(Arrays.areEqual(r1, r2));
    }

    private static void checkIllegalArgument(byte[] encrypted, RSAKeyParameters key, int version)
    {
        try
        {
            TlsRSAUtils.decryptPreMasterSecret(encrypted, key, version, RANDOM);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    /**
     * Check a bad ciphertext gives a fresh random 48 byte value each time, never the (invalid) decrypted
     * contents, and without raising an exception.
     */
    private static void checkImplicitRejection(String label, byte[] encrypted, RSAKeyParameters privKey,
        byte[] embedded)
    {
        TlsContext context = createServerContext(ProtocolVersion.TLSv12, RANDOM);

        byte[] r1, r2, r3, r4;
        try
        {
            r1 = TlsRSAUtils.decryptPreMasterSecret(encrypted, privKey, TLS12, RANDOM);
            r2 = TlsRSAUtils.decryptPreMasterSecret(encrypted, privKey, TLS12, RANDOM);
            r3 = TlsRSAUtils.decryptPreMasterSecret(encrypted, withoutCrt(privKey), TLS12, RANDOM);
            r4 = TlsRSAUtils.safeDecryptPreMasterSecret(context, privKey, encrypted);
        }
        catch (RuntimeException e)
        {
            fail(label + ": exception thrown: " + e);
            return;
        }

        assertEquals(label, 48, r1.length);
        assertEquals(label, 48, r2.length);
        assertEquals(label, 48, r3.length);
        assertEquals(label, 48, r4.length);

        assertFalse(label + ": result not random", Arrays.areEqual(r1, r2));
        assertFalse(label + ": result not random", Arrays.areEqual(r1, r4));

        if (embedded != null)
        {
            assertFalse(label + ": decrypted data returned", Arrays.areEqual(embedded, r1));
            assertFalse(label + ": decrypted data returned", Arrays.areEqual(embedded, r2));
            assertFalse(label + ": decrypted data returned", Arrays.areEqual(embedded, r3));
            assertFalse(label + ": decrypted data returned", Arrays.areEqual(embedded, r4));
        }
    }

    private static byte[] toUnsigned(BigInteger value)
    {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0)
        {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
