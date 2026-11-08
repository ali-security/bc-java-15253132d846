package org.bouncycastle.jce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * The JCA "SHA256withRSA" verifier must check every hash byte of a DigestInfo that leaves out the
 * NULL parameters (CVE-2026-12860; the JCA DigestSignatureSpi has the same loop as RSADigestSigner).
 */
public class RSANoNullDigestInfoTest
    extends SimpleTest
{
    public String getName()
    {
        return "RSANoNullDigestInfo";
    }

    public void performTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        byte[] msg = new byte[] { 1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23 };
        byte[] hash = MessageDigest.getInstance("SHA-256", "BC").digest(msg);

        byte[] tampered = Arrays.clone(hash);
        tampered[tampered.length - 1] ^= 0x01;
        tampered[tampered.length - 2] ^= (byte)0x80;

        Signature verifier = Signature.getInstance("SHA256withRSA", "BC");

        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        if (!verifier.verify(signNoNull((RSAPrivateCrtKey)kp.getPrivate(), hash)))
        {
            fail("no-NULL DigestInfo with the correct hash must verify");
        }

        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        if (verifier.verify(signNoNull((RSAPrivateCrtKey)kp.getPrivate(), tampered)))
        {
            fail("no-NULL DigestInfo with wrong final hash bytes must be rejected");
        }
    }

    private static byte[] signNoNull(RSAPrivateCrtKey k, byte[] hash)
        throws Exception
    {
        byte[] enc = new DigestInfo(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), hash).getEncoded(ASN1Encoding.DER);

        AsymmetricBlockCipher rsa = new PKCS1Encoding(new RSABlindedEngine());
        rsa.init(true, new RSAPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(),
            k.getPrimeP(), k.getPrimeQ(), k.getPrimeExponentP(), k.getPrimeExponentQ(), k.getCrtCoefficient()));
        return rsa.processBlock(enc, 0, enc.length);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new RSANoNullDigestInfoTest());
    }
}
