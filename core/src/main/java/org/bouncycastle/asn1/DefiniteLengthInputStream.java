package org.bouncycastle.asn1;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

class DefiniteLengthInputStream
        extends LimitedInputStream
{
    private static final byte[] EMPTY_BYTES = new byte[0];

    private final int _originalLength;
    private int _remaining;

    DefiniteLengthInputStream(
        InputStream in,
        int         length)
    {
        super(in, length);

        if (length < 0)
        {
            throw new IllegalArgumentException("negative lengths not allowed");
        }

        this._originalLength = length;
        this._remaining = length;

        if (length == 0)
        {
            setParentEofDetect(true);
        }
    }

    int getRemaining()
    {
        return _remaining;
    }

    public int read()
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int b = _in.read();

        if (b < 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }

        if (--_remaining == 0)
        {
            setParentEofDetect(true);
        }

        return b;
    }

    public int read(byte[] buf, int off, int len)
        throws IOException
    {
        if (_remaining == 0)
        {
            return -1;
        }

        int toRead = Math.min(len, _remaining);
        int numRead = _in.read(buf, off, toRead);

        if (numRead < 0)
        {
            throw new EOFException("DEF length " + _originalLength + " object truncated by " + _remaining);
        }

        if ((_remaining -= numRead) == 0)
        {
            setParentEofDetect(true);
        }

        return numRead;
    }

    byte[] toByteArray()
        throws IOException
    {
        if (_remaining == 0)
        {
            return EMPTY_BYTES;
        }

        // Read through this stream (not _in) so Streams.readLenBytesFully grows the buffer as bytes
        // arrive - avoiding the eager new byte[_remaining] that let a short crafted header drive a
        // heap-sized allocation before any data was read (CWE-789) - while read(byte[], int, int)
        // above keeps the _remaining / parent-EOF bookkeeping and reports a truncated stream with the
        // established "DEF length ... object truncated by ..." EOFException.
        return Streams.readLenBytesFully(this, _remaining);
    }
}
