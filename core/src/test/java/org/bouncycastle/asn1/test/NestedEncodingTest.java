package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERExternal;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Check that the DER encoding of crafted, deeply nested SET and EXTERNAL structures does
 * not consume resources exponential in the nesting depth (CVE-2023-33202).
 */
public class NestedEncodingTest
    extends SimpleTest
{
    private static final long TIMEOUT = 30000;

    private static final int DEPTH = 64;

    private static final byte[] NULL_ENC = { BERTags.NULL, 0x00 };

    public String getName()
    {
        return "NestedEncoding";
    }

    public void performTest()
        throws Exception
    {
        unsortedSetTest();
        nestedSetVisitCountTest();
        parsedNestedSetTest();
        parsedNestedTaggedSetTest();
        parsedNestedExternalTest();
        externalLengthTest();
        externalTaggedConstructorTest();
    }

    /*
     * DER conversion of an unsorted set sorts a copy - the set keeps its own order, and
     * repeated conversions give the same encoding as the equivalent DERSet.
     */
    private void unsortedSetTest()
        throws Exception
    {
        byte[] data = new byte[10];
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DEROctetString(data));
        v.add(new DERBitString(data));
        v.add(new ASN1Integer(100));
        v.add(ASN1Boolean.getInstance(true));

        ASN1Set dlSet = new DLSet(v);
        byte[] expected = new DERSet(v).getEncoded();

        for (int i = 0; i != 3; i++)
        {
            isTrue("DER encoding of DLSet wrong on attempt " + i, areEqual(expected, dlSet.getEncoded(ASN1Encoding.DER)));
        }

        isTrue("DLSet order changed by DER encoding", dlSet.getObjectAt(0) instanceof DEROctetString);
        isTrue("DL encoding of DLSet sorted", dlSet.getEncoded(ASN1Encoding.DL)[2] == BERTags.OCTET_STRING);
        isTrue("DER encoding of SEQUENCE containing DLSet wrong",
            areEqual(new DERSequence(new DERSet(v)).getEncoded(), new DERSequence(dlSet).getEncoded(ASN1Encoding.DER)));
    }

    /*
     * Each level of unsorted sets must be sorted only once, so the number of times the leaf
     * is visited during DER encoding stays polynomial in the depth.
     */
    private void nestedSetVisitCountTest()
        throws Exception
    {
        int depth = 16;
        CountingInteger leaf = new CountingInteger();
        ASN1Encodable unsorted = leaf;
        ASN1Encodable sorted = new ASN1Integer(1);

        for (int i = 0; i != depth; i++)
        {
            unsorted = new DLSet(new ASN1Encodable[]{ unsorted, DERNull.INSTANCE });
            sorted = new DERSet(new ASN1Encodable[]{ sorted, DERNull.INSTANCE });
        }

        byte[] expected = sorted.toASN1Primitive().getEncoded(ASN1Encoding.DER);

        leaf.count = 0;

        byte[] encoded = encodeWithTimeout(unsorted, ASN1Encoding.DER);

        isTrue("nested DLSet DER encoding wrong", areEqual(expected, encoded));
        isTrue("leaf of nested SETs visited " + leaf.count + " times", leaf.count <= 4 * depth * depth);
    }

    /*
     * SET { SET { ... SET { NULL, NULL } ..., NULL }, NULL } - unsorted on the wire, so each
     * level needs sorting for DER.
     */
    private void parsedNestedSetTest()
        throws Exception
    {
        byte[] input = NULL_ENC;
        byte[] expected = NULL_ENC;

        for (int i = 0; i != DEPTH; i++)
        {
            input = tlv(BERTags.SET | BERTags.CONSTRUCTED, Arrays.concatenate(input, NULL_ENC));
            expected = tlv(BERTags.SET | BERTags.CONSTRUCTED, Arrays.concatenate(NULL_ENC, expected));
        }

        ASN1Primitive parsed = ASN1Primitive.fromByteArray(input);

        isTrue("nested SET not parsed as a set", parsed instanceof ASN1Set);
        isTrue("nested SET DER encoding wrong", areEqual(expected, encodeWithTimeout(parsed, ASN1Encoding.DER)));
        isTrue("nested SET DL encoding wrong", areEqual(input, encodeWithTimeout(parsed, ASN1Encoding.DL)));
        isTrue("nested SET DER encoding wrong on repeat", areEqual(expected, encodeWithTimeout(parsed, ASN1Encoding.DER)));
    }

    /*
     * [0] { SET { [0] { SET { ... }, NULL } }, NULL } - a tagged object converts its contents to
     * DER, even in the default encoding, so a DER set must not be sorted again.
     */
    private void parsedNestedTaggedSetTest()
        throws Exception
    {
        byte[] input = NULL_ENC;
        byte[] expected = NULL_ENC;

        for (int i = 0; i != DEPTH; i++)
        {
            input = tlv(BERTags.TAGGED | BERTags.CONSTRUCTED,
                tlv(BERTags.SET | BERTags.CONSTRUCTED, Arrays.concatenate(input, NULL_ENC)));
            expected = tlv(BERTags.TAGGED | BERTags.CONSTRUCTED,
                tlv(BERTags.SET | BERTags.CONSTRUCTED, Arrays.concatenate(NULL_ENC, expected)));
        }

        ASN1Primitive parsed = ASN1Primitive.fromByteArray(input);

        isTrue("nested tagged SET not parsed as a tagged object", parsed instanceof ASN1TaggedObject);
        isTrue("nested tagged SET encoding wrong", areEqual(expected, encodeWithTimeout(parsed, null)));
        isTrue("nested tagged SET DER encoding wrong", areEqual(expected, encodeWithTimeout(parsed, ASN1Encoding.DER)));
    }

    /*
     * EXTERNAL { [0] EXTERNAL { [0] ... NULL } } - the length of an EXTERNAL must not require
     * a full encoding of its content.
     */
    private void parsedNestedExternalTest()
        throws Exception
    {
        byte[] input = NULL_ENC;

        for (int i = 0; i != DEPTH; i++)
        {
            input = tlv(BERTags.EXTERNAL | BERTags.CONSTRUCTED, tlv(BERTags.TAGGED | BERTags.CONSTRUCTED, input));
        }

        ASN1Primitive parsed = ASN1Primitive.fromByteArray(input);

        isTrue("nested EXTERNAL not parsed as an EXTERNAL", parsed instanceof DERExternal);
        isTrue("nested EXTERNAL DER encoding wrong", areEqual(input, encodeWithTimeout(parsed, ASN1Encoding.DER)));
        isTrue("nested EXTERNAL encoding wrong", areEqual(input, encodeWithTimeout(parsed, null)));
        isTrue("nested EXTERNAL length wrong", areEqual(tlv(BERTags.SEQUENCE | BERTags.CONSTRUCTED, input),
            encodeWithTimeout(new DERSequence(parsed), ASN1Encoding.DER)));
    }

    /*
     * The computed length of an EXTERNAL must match its encoding for all optional components
     * and multi-byte lengths.
     */
    private void externalLengthTest()
        throws Exception
    {
        DERExternal inner = new DERExternal(new ASN1ObjectIdentifier("1.2.3"), new ASN1Integer(7),
            new DERPrintableString("descriptor"), 1, new DEROctetString(new byte[200]));
        DERExternal outer = new DERExternal(new ASN1ObjectIdentifier("1.2.3.4"), new ASN1Integer(1000),
            inner, 0, new DEROctetString(new byte[300]));

        ASN1Encodable[] externals = new ASN1Encodable[]{ inner, outer };

        for (int i = 0; i != externals.length; i++)
        {
            byte[] enc = externals[i].toASN1Primitive().getEncoded(ASN1Encoding.DER);

            isTrue("EXTERNAL length wrong " + i,
                areEqual(tlv(BERTags.SEQUENCE | BERTags.CONSTRUCTED, enc), new DERSequence(externals[i]).getEncoded()));
            isTrue("EXTERNAL round trip failed " + i, externals[i].equals(ASN1Primitive.fromByteArray(enc)));
        }
    }

    /*
     * The external data passed as a tagged object is the content of the tagged object, not
     * the tagged object itself.
     */
    private void externalTaggedConstructorTest()
        throws Exception
    {
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.3.4");
        ASN1Integer data = new ASN1Integer(42);

        DERExternal fromTagged = new DERExternal(oid, null, null, new DERTaggedObject(true, 1, data));
        DERExternal fromParts = new DERExternal(oid, null, null, 1, data);

        isTrue("EXTERNAL encoding wrong", fromTagged.getEncoding() == 1);
        isTrue("EXTERNAL content not unwrapped", data.equals(fromTagged.getExternalContent()));
        isTrue("EXTERNAL encodings differ", areEqual(fromParts.getEncoded(), fromTagged.getEncoded()));
        isTrue("EXTERNAL round trip failed", fromTagged.equals(ASN1Primitive.fromByteArray(fromTagged.getEncoded())));
    }

    private byte[] encodeWithTimeout(final ASN1Encodable obj, final String encoding)
        throws Exception
    {
        final Object[] result = new Object[1];

        Thread t = new Thread(new Runnable()
        {
            public void run()
            {
                try
                {
                    if (encoding == null)
                    {
                        result[0] = obj.toASN1Primitive().getEncoded();
                    }
                    else
                    {
                        result[0] = obj.toASN1Primitive().getEncoded(encoding);
                    }
                }
                catch (Throwable e)
                {
                    result[0] = e;
                }
            }
        }, "NestedEncodingTest");

        t.setDaemon(true);
        t.start();
        t.join(TIMEOUT);

        if (t.isAlive())
        {
            fail("encoding did not complete within " + TIMEOUT + "ms");
        }

        if (result[0] instanceof Throwable)
        {
            fail("encoding failed: " + result[0], (Throwable)result[0]);
        }

        return (byte[])result[0];
    }

    private static byte[] tlv(int tag, byte[] contents)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int length = contents.length;

        bOut.write(tag);

        if (length > 127)
        {
            int size = 1;
            int val = length;

            while ((val >>>= 8) != 0)
            {
                size++;
            }

            bOut.write(size | 0x80);

            for (int i = (size - 1) * 8; i >= 0; i -= 8)
            {
                bOut.write(length >> i);
            }
        }
        else
        {
            bOut.write(length);
        }

        bOut.write(contents, 0, contents.length);

        return bOut.toByteArray();
    }

    private static class CountingInteger
        extends ASN1Object
    {
        volatile int count = 0;

        public ASN1Primitive toASN1Primitive()
        {
            count++;

            return new ASN1Integer(1);
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new NestedEncodingTest());
    }
}
