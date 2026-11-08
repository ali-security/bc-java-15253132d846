package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.TlsUtils;

/**
 * CVE-2026-59646: the DTLS handshake reassembler must not accept a handshake message whose declared
 * length exceeds the peer's maximum handshake message size (32768 by default). Before the fix the
 * reassembly buffer was allocated from the attacker-controlled 24-bit length.
 */
public class DTLSHandshakeLimitTest
    extends TestCase
{
    private static final int DECLARED_LENGTH = 40000;
    private static final int FRAGMENT_LENGTH = 1000;

    static class EndOfInput
        extends RuntimeException
    {
    }

    /**
     * Delivers a complete (all-zero) ClientHello that declares DECLARED_LENGTH bytes, in fragments,
     * and then ends the handshake with EndOfInput.
     */
    static class OversizedClientHelloTransport
        implements DatagramTransport
    {
        private int offset = 0;
        private long recordSeq = 0;

        public int getReceiveLimit()
        {
            return 1500;
        }

        public int getSendLimit()
        {
            return 1500;
        }

        public int receive(byte[] buf, int off, int len, int waitMillis)
            throws IOException
        {
            if (offset >= DECLARED_LENGTH)
            {
                throw new EndOfInput();
            }

            int fragmentLength = Math.min(FRAGMENT_LENGTH, DECLARED_LENGTH - offset);
            int recordLength = 12 + fragmentLength;

            byte[] record = new byte[13 + recordLength];
            TlsUtils.writeUint8((short)22, record, 0);          // handshake
            record[1] = (byte)0xFE;
            record[2] = (byte)0xFF;                             // DTLS 1.0
            TlsUtils.writeUint16(0, record, 3);                 // epoch
            TlsUtils.writeUint48(recordSeq++, record, 5);
            TlsUtils.writeUint16(recordLength, record, 11);

            TlsUtils.writeUint8((short)1, record, 13);          // client_hello
            TlsUtils.writeUint24(DECLARED_LENGTH, record, 14);
            TlsUtils.writeUint16(0, record, 17);                // message_seq
            TlsUtils.writeUint24(offset, record, 19);
            TlsUtils.writeUint24(fragmentLength, record, 22);

            offset += fragmentLength;

            System.arraycopy(record, 0, buf, off, record.length);
            return record.length;
        }

        public void send(byte[] buf, int off, int len)
            throws IOException
        {
        }

        public void close()
            throws IOException
        {
        }
    }

    public void testOversizedHandshakeMessageIsIgnored()
        throws Exception
    {
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol(new SecureRandom());

        try
        {
            serverProtocol.accept(new MockDTLSServer(), new OversizedClientHelloTransport());
            fail("accept() must not complete");
        }
        catch (Exception e)
        {
            // accept() reports a RuntimeException from the transport as internal_error with the
            // exception as its cause. EndOfInput as the cause means the oversized message was
            // never reassembled or processed.
            if (!(e instanceof EndOfInput) && !(e.getCause() instanceof EndOfInput))
            {
                fail("oversized handshake message was reassembled and processed: " + e);
            }
        }
    }
}
