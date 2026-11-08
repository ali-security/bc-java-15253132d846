package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * RFC 5652 sec. 9.1 pairs the digestAlgorithm and authAttrs fields of an AuthenticatedData:
 * the MAC covers the DER encoding of authAttrs when they are present and the content directly
 * when they are not. A parsed AuthenticatedData whose two fields disagree must be rejected,
 * otherwise attributes inserted into a digestAlgorithm-absent message would be handed back as
 * though the (content-only) MAC had authenticated them.
 */
public class AuthenticatedDataTest
    extends SimpleTest
{
    private static final String MISMATCH = "digestAlgorithm and authAttrs must be set together";

    private static final byte[] CONTENT = "Eric H. Echidna".getBytes();

    public String getName()
    {
        return "AuthenticatedData";
    }

    public void performTest()
        throws Exception
    {
        wellFormedTest();
        digestAbsentAuthAttrsPresentTest();
        forgedAuthAttrsTest();
        digestPresentAuthAttrsAbsentTest();
        publicConstructorTest();
    }

    /*
     * Messages where digestAlgorithm and authAttrs are both absent, or both present, still parse.
     */
    private void wellFormedTest()
        throws Exception
    {
        AuthenticatedData noAttrs = new AuthenticatedData(null, recipientInfos(), macAlgorithm(), null,
            encapContentInfo(), null, mac(), null);

        AuthenticatedData parsed = AuthenticatedData.getInstance(ASN1Primitive.fromByteArray(noAttrs.getEncoded()));

        isTrue("digestAlgorithm should be absent", parsed.getDigestAlgorithm() == null);
        isTrue("authAttrs should be absent", parsed.getAuthAttrs() == null);
        isTrue("unauthAttrs should be absent", parsed.getUnauthAttrs() == null);
        isTrue("mac mismatch", Arrays.areEqual(mac().getOctets(), parsed.getMac().getOctets()));

        AuthenticatedData withAttrs = new AuthenticatedData(null, recipientInfos(), macAlgorithm(),
            digestAlgorithm(), encapContentInfo(), authAttrs(), mac(), unauthAttrs());

        parsed = AuthenticatedData.getInstance(ASN1Primitive.fromByteArray(withAttrs.getEncoded()));

        isTrue("digestAlgorithm should be present", digestAlgorithm().equals(parsed.getDigestAlgorithm()));
        isTrue("authAttrs should be present", authAttrs().equals(parsed.getAuthAttrs()));
        isTrue("unauthAttrs should be present", unauthAttrs().equals(parsed.getUnauthAttrs()));
        isTrue("well formed encoding changed", Arrays.areEqual(withAttrs.getEncoded(ASN1Encoding.DER),
            parsed.getEncoded(ASN1Encoding.DER)));

        // both absent, with unauthAttrs following the MAC, and with an originatorInfo shifting the indices
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(new DERTaggedObject(false, 0, new DERSequence()));
        v.add(recipientInfos());
        v.add(macAlgorithm());
        v.add(encapContentInfo());
        v.add(mac());
        v.add(new DERTaggedObject(false, 3, unauthAttrs()));

        parsed = AuthenticatedData.getInstance(ASN1Primitive.fromByteArray(new DERSequence(v).getEncoded()));

        isTrue("originatorInfo should be present", parsed.getOriginatorInfo() != null);
        isTrue("digestAlgorithm should be absent", parsed.getDigestAlgorithm() == null);
        isTrue("authAttrs should be absent", parsed.getAuthAttrs() == null);
        isTrue("unauthAttrs should be present", parsed.getUnauthAttrs() != null);
    }

    /*
     * authAttrs [2] present with digestAlgorithm [1] absent - the MAC of such a message only ever
     * covers the content, so the attributes are unauthenticated.
     */
    private void digestAbsentAuthAttrsPresentTest()
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(recipientInfos());
        v.add(macAlgorithm());
        v.add(encapContentInfo());
        v.add(new DERTaggedObject(false, 2, authAttrs()));
        v.add(mac());

        checkRejected("authAttrs without digestAlgorithm", new DERSequence(v));

        // ... with unauthAttrs following the MAC
        v.add(new DERTaggedObject(false, 3, unauthAttrs()));

        checkRejected("authAttrs without digestAlgorithm, unauthAttrs present", new DERSequence(v));

        // ... with an originatorInfo shifting the indices
        v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(new DERTaggedObject(false, 0, new DERSequence()));
        v.add(recipientInfos());
        v.add(macAlgorithm());
        v.add(encapContentInfo());
        v.add(new DERTaggedObject(false, 2, authAttrs()));
        v.add(mac());

        checkRejected("authAttrs without digestAlgorithm, originatorInfo present", new DERSequence(v));
    }

    /*
     * The attack: take a genuine digestAlgorithm-absent message (MAC over the content alone) and
     * insert an attacker-chosen authAttrs set, leaving digestAlgorithm absent and the MAC untouched.
     */
    private void forgedAuthAttrsTest()
        throws Exception
    {
        AuthenticatedData genuine = new AuthenticatedData(null, recipientInfos(), macAlgorithm(), null,
            encapContentInfo(), null, mac(), null);
        ContentInfo original = new ContentInfo(CMSObjectIdentifiers.authenticatedData, genuine);

        ContentInfo received = ContentInfo.getInstance(ASN1Primitive.fromByteArray(original.getEncoded()));
        AuthenticatedData authData = AuthenticatedData.getInstance(received.getContent());

        ASN1Set forgedAuthAttrs = new DERSet(
            new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(authData.getVersion());
        v.add(authData.getRecipientInfos());
        v.add(authData.getMacAlgorithm());
        v.add(authData.getEncapsulatedContentInfo());
        v.add(new DERTaggedObject(false, 2, forgedAuthAttrs));
        v.add(authData.getMac());

        ContentInfo forged = new ContentInfo(CMSObjectIdentifiers.authenticatedData, new DLSequence(v));

        ContentInfo forgedReceived = ContentInfo.getInstance(ASN1Primitive.fromByteArray(forged.getEncoded()));

        checkRejected("forged authAttrs", forgedReceived.getContent());

        // and through the tagged-object accessor
        try
        {
            AuthenticatedData.getInstance(new DERTaggedObject(true, 0, forgedReceived.getContent()), true);
            fail("tagged AuthenticatedData must reject authAttrs without digestAlgorithm");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message: " + e.getMessage(), MISMATCH.equals(e.getMessage()));
        }
    }

    /*
     * The mirror: digestAlgorithm [1] present commits a verifier to MACing DER(authAttrs), so a
     * message that then omits authAttrs is malformed too.
     */
    private void digestPresentAuthAttrsAbsentTest()
        throws Exception
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        v.add(recipientInfos());
        v.add(macAlgorithm());
        v.add(new DERTaggedObject(false, 1, digestAlgorithm()));
        v.add(encapContentInfo());
        v.add(mac());

        checkRejected("digestAlgorithm without authAttrs", new DERSequence(v));

        // ... with unauthAttrs following the MAC
        v.add(new DERTaggedObject(false, 3, unauthAttrs()));

        checkRejected("digestAlgorithm without authAttrs, unauthAttrs present", new DERSequence(v));

        // stripping authAttrs from a genuine digestAlgorithm-present message
        AuthenticatedData genuine = new AuthenticatedData(null, recipientInfos(), macAlgorithm(),
            digestAlgorithm(), encapContentInfo(), authAttrs(), mac(), null);
        AuthenticatedData authData = AuthenticatedData.getInstance(ASN1Primitive.fromByteArray(genuine.getEncoded()));

        v = new ASN1EncodableVector();
        v.add(authData.getVersion());
        v.add(authData.getRecipientInfos());
        v.add(authData.getMacAlgorithm());
        v.add(new DERTaggedObject(false, 1, authData.getDigestAlgorithm()));
        v.add(authData.getEncapsulatedContentInfo());
        v.add(authData.getMac());

        checkRejected("stripped authAttrs", new DLSequence(v));
    }

    /*
     * The public constructor already enforced the pairing - make sure it still does.
     */
    private void publicConstructorTest()
    {
        try
        {
            new AuthenticatedData(null, recipientInfos(), macAlgorithm(), null, encapContentInfo(),
                authAttrs(), mac(), null);
            fail("constructor must reject authAttrs without digestAlgorithm");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message: " + e.getMessage(), MISMATCH.equals(e.getMessage()));
        }

        try
        {
            new AuthenticatedData(null, recipientInfos(), macAlgorithm(), digestAlgorithm(), encapContentInfo(),
                null, mac(), null);
            fail("constructor must reject digestAlgorithm without authAttrs");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("wrong message: " + e.getMessage(), MISMATCH.equals(e.getMessage()));
        }
    }

    private void checkRejected(String label, ASN1Encodable authData)
        throws Exception
    {
        // as constructed
        try
        {
            AuthenticatedData.getInstance(authData);
            fail(label + ": AuthenticatedData accepted mismatched digestAlgorithm/authAttrs");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(label + ": wrong message: " + e.getMessage(), MISMATCH.equals(e.getMessage()));
        }

        // as received off the wire
        byte[] encoding = authData.toASN1Primitive().getEncoded();
        try
        {
            AuthenticatedData.getInstance(ASN1Primitive.fromByteArray(encoding));
            fail(label + ": AuthenticatedData accepted mismatched digestAlgorithm/authAttrs from encoding");
        }
        catch (IllegalArgumentException e)
        {
            isTrue(label + ": wrong message: " + e.getMessage(), MISMATCH.equals(e.getMessage()));
        }
    }

    private static ASN1Set recipientInfos()
    {
        KeyTransRecipientInfo ktri = new KeyTransRecipientInfo(
            new RecipientIdentifier(new DEROctetString(new byte[] { 1, 2, 3, 4, 5 })),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
            new DEROctetString(new byte[64]));

        return new DERSet(new RecipientInfo(ktri));
    }

    private static AlgorithmIdentifier macAlgorithm()
    {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.des_EDE3_CBC, new DEROctetString(new byte[8]));
    }

    private static AlgorithmIdentifier digestAlgorithm()
    {
        return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
    }

    private static ContentInfo encapContentInfo()
    {
        return new ContentInfo(CMSObjectIdentifiers.data, new DEROctetString(CONTENT));
    }

    private static ASN1Set authAttrs()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new Attribute(CMSAttributes.contentType, new DERSet(CMSObjectIdentifiers.data)));
        v.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(new byte[20]))));

        return new DERSet(v);
    }

    private static ASN1Set unauthAttrs()
    {
        return new DERSet(new Attribute(CMSAttributes.signingTime, new DERSet(new DEROctetString(new byte[1]))));
    }

    private static DEROctetString mac()
    {
        return new DEROctetString(new byte[] { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11 });
    }

    public static void main(
        String[] args)
    {
        runTest(new AuthenticatedDataTest());
    }
}
