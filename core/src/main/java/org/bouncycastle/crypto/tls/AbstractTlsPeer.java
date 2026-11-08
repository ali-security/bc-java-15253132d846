package org.bouncycastle.crypto.tls;

import java.io.IOException;

public abstract class AbstractTlsPeer
    implements TlsPeer
{
    public boolean shouldUseGMTUnixTime()
    {
        /*
         * draft-mathewson-no-gmtunixtime-00 2. For the reasons we discuss above, we recommend that
         * TLS implementors MUST by default set the entire value the ClientHello.Random and
         * ServerHello.Random fields, including gmt_unix_time, to a cryptographically random
         * sequence.
         */
        return false;
    }

    public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException
    {
        if (!secureRenegotiation)
        {
            /*
             * RFC 5746 3.4/3.6. In this case, some clients/servers may want to terminate the handshake instead
             * of continuing; see Section 4.1/4.3 for discussion.
             */
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
    }

    public void notifyHandshakeComplete() throws IOException
    {
    }

    /**
     * Return the maximum size (in bytes) that a DTLS handshake message received from the peer may
     * declare. A declared length above this value is ignored before any reassembly buffer is
     * allocated (CVE-2026-59646). Values below 1024 are raised to 1024.
     */
    public int getMaxHandshakeMessageSize()
    {
        return 32768;
    }
}
