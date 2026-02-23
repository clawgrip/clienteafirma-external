package com.aowagie.text.pdf.bouncycastle;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;

/**
 * A wrapper class that allows block ciphers to be used to process data in
 * a piecemeal fashion. The BufferedBlockCipher outputs a block only when the
 * buffer is full and more data is being added, or on a doFinal.
 * <p>
 * Note: in the case where the underlying cipher is either a CFB cipher or an
 * OFB one the last block may not be a multiple of the block size. Use this class
 * for construction rather than BufferedBlockCipher as BufferedBlockCipher will eventually
 * turn into an interface.
 */
public class DefaultBufferedBlockCipher
    extends BufferedBlockCipher
{
    protected byte[]        buf;
    protected int           bufOff;

    protected boolean          forEncryption;
    protected BlockCipher      cipher;
    protected MultiBlockCipher mbCipher;

    protected boolean       partialBlockOkay;
    protected boolean       pgpCFB;

    /**
     * constructor for subclasses
     */
    protected DefaultBufferedBlockCipher()
    {
    }

    /**
     * Create a buffered block cipher without padding.
     *
     * @param cipher the underlying block cipher this buffering object wraps.
     */
    public DefaultBufferedBlockCipher(final BlockCipher cipher) {

    	super(cipher);

        this.cipher = cipher;

        if (cipher instanceof MultiBlockCipher) {
            this.mbCipher = (MultiBlockCipher)cipher;
            buf = new byte[mbCipher.getMultiBlockSize()];
        }
        else {
            this.mbCipher = null;
            buf = new byte[cipher.getBlockSize()];
        }

        bufOff = 0;

        //
        // check if we can handle partial blocks on doFinal.
        //
        final String  name = cipher.getAlgorithmName();
        final int     idx = name.indexOf('/') + 1;

        pgpCFB = idx > 0 && name.startsWith("PGP", idx);

        if (pgpCFB || cipher instanceof StreamCipher)
        {
            partialBlockOkay = true;
        }
        else
        {
            partialBlockOkay = idx > 0 && name.startsWith("OpenPGP", idx);
        }
    }

    /**
     * return the cipher this object wraps.
     *
     * @return the cipher this object wraps.
     */
    @Override
	public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    /**
     * initialise the cipher.
     *
     * @param forEncryption if true the cipher is initialised for
     *  encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    @Override
	public void init(
        final boolean             forEncryption,
        final CipherParameters    params)
        throws IllegalArgumentException
    {
        this.forEncryption = forEncryption;

        reset();

        cipher.init(forEncryption, params);
    }

    /**
     * return the blocksize for the underlying cipher.
     *
     * @return the blocksize for the underlying cipher.
     */
    @Override
	public int getBlockSize()
    {
        return cipher.getBlockSize();
    }

    /**
     * return the size of the output buffer required for an update
     * an input of len bytes.
     *
     * @param len the length of the input.
     * @return the space required to accommodate a call to update
     * with len bytes of input.
     */
    @Override
	public int getUpdateOutputSize(
        final int len)
    {
        final int total       = len + bufOff;
        int leftOver;

        if (pgpCFB && forEncryption)
		{
		    leftOver = total % buf.length - (cipher.getBlockSize() + 2);
		}
		else
		{
		    leftOver = total % buf.length;
		}

        return total - leftOver;
    }

    /**
     * return the size of the output buffer required for an update plus a
     * doFinal with an input of 'length' bytes.
     *
     * @param length the length of the input.
     * @return the space required to accommodate a call to update and doFinal
     * with 'length' bytes of input.
     */
    @Override
	public int getOutputSize(
        final int length)
    {
        if (pgpCFB && forEncryption)
        {
            return length + bufOff + cipher.getBlockSize() + 2;
        }

        // Note: Can assume partialBlockOkay is true for purposes of this calculation
        return length + bufOff;
    }

    /**
     * process a single byte, producing an output block if necessary.
     *
     * @param in the input byte.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    @Override
	public int processByte(
        final byte        in,
        final byte[]      out,
        final int         outOff)
        throws DataLengthException, IllegalStateException
    {
        int         resultLen = 0;

        buf[bufOff++] = in;

        if (bufOff == buf.length)
        {
            resultLen = cipher.processBlock(buf, 0, out, outOff);
            bufOff = 0;
        }

        return resultLen;
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param in the input byte array.
     * @param inOff the offset at which the input data starts.
     * @param len the number of bytes to be copied out of the input array.
     * @param out the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    @Override
	public int processBytes(
        final byte[]      in,
        int         inOff,
        int         len,
        final byte[]      out,
        final int         outOff)
        throws DataLengthException, IllegalStateException
    {
        if (len < 0)
        {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }

        final int blockSize   = getBlockSize();
        final int length      = getUpdateOutputSize(len);

        if (length > 0 && outOff + length > out.length)
		{
		    throw new OutputLengthException("output buffer too short");
		}

        int resultLen = 0;
        final int gapLen = buf.length - bufOff;

        if (len > gapLen)
        {
            System.arraycopy(in, inOff, buf, bufOff, gapLen);

            resultLen += cipher.processBlock(buf, 0, out, outOff);

            bufOff = 0;
            len -= gapLen;
            inOff += gapLen;

            if (mbCipher != null)
            {
                final int blockCount = len / mbCipher.getMultiBlockSize();

                if (blockCount > 0)
                {
                    resultLen += mbCipher.processBlocks(in, inOff, blockCount, out, outOff + resultLen);

                    final int processed = blockCount * mbCipher.getMultiBlockSize();

                    len -= processed;
                    inOff += processed;
                }
            }
            else
            {
                while (len > buf.length)
                {
                    resultLen += cipher.processBlock(in, inOff, out, outOff + resultLen);

                    len -= blockSize;
                    inOff += blockSize;
                }
            }
        }

        System.arraycopy(in, inOff, buf, bufOff, len);

        bufOff += len;

        if (bufOff == buf.length)
        {
            resultLen += cipher.processBlock(buf, 0, out, outOff + resultLen);
            bufOff = 0;
        }

        return resultLen;
    }

    /**
     * Process the last block in the buffer.
     *
     * @param out the array the block currently being held is copied into.
     * @param outOff the offset at which the copying starts.
     * @return the number of output bytes copied to out.
     * @exception DataLengthException if there is insufficient space in out for
     * the output, or the input is not block size aligned and should be.
     * @exception IllegalStateException if the underlying cipher is not
     * initialised.
     * @exception InvalidCipherTextException if padding is expected and not found.
     * @exception DataLengthException if the input is not block size
     * aligned.
     */
    @Override
	public int doFinal(
        final byte[]  out,
        final int     outOff)
        throws DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        try
        {
            int resultLen = 0;

            if (outOff + bufOff > out.length)
            {
                throw new OutputLengthException("output buffer too short for doFinal()");
            }

            if (bufOff != 0)
            {
                if (!partialBlockOkay)
                {
                    throw new DataLengthException("data not block size aligned");
                }

                cipher.processBlock(buf, 0, buf, 0);
                resultLen = bufOff;
                bufOff = 0;
                System.arraycopy(buf, 0, out, outOff, resultLen);
            }

            return resultLen;
        }
        finally
        {
            reset();
        }
    }

    /**
     * Reset the buffer and cipher. After resetting the object is in the same
     * state as it was after the last init (if there was one).
     */
    @Override
	public void reset()
    {
        //
        // clean the buffer.
        //
        for (int i = 0; i < buf.length; i++)
        {
            buf[i] = 0;
        }

        bufOff = 0;

        //
        // reset the underlying cipher.
        //
        cipher.reset();
    }
}
