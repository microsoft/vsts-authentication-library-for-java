// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.common.helpers;

import com.microsoft.alm.common.helpers.IOHelper;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Random;

/**
 * A class to test {@link IOHelper}.
 */
public class IOHelperTest {

    private static byte[] createRandomByteArray(final int numberOfBytes) {
        final Random random = new Random(42);
        final byte[] result = new byte[numberOfBytes];
        random.nextBytes(result);
        return result;
    }

    private static void testCopyStream(final int numberOfBytes) throws IOException {
        final byte[] input = createRandomByteArray(numberOfBytes);
        final ByteArrayInputStream bais = new ByteArrayInputStream(input);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream(numberOfBytes);

        IOHelper.copyStream(bais, baos);

        final byte[] actual = baos.toByteArray();
        Assert.assertArrayEquals(input, actual);
        Assert.assertEquals(numberOfBytes, baos.size());
    }

    @Test
    public void copyStream_zeroBuffer() throws Exception {
        testCopyStream(0);
    }

    @Test
    public void copyStream_oneByte() throws Exception {
        testCopyStream(1);
    }

    @Test
    public void copyStream_halfSmallerThanBuffer() throws Exception {
        testCopyStream(IOHelper.BUFFER_SIZE / 2);
    }

    @Test
    public void copyStream_justSmallerThanBuffer() throws Exception {
        testCopyStream(IOHelper.BUFFER_SIZE - 1);
    }

    @Test
    public void copyStream_sameAsBuffer() throws Exception {
        testCopyStream(IOHelper.BUFFER_SIZE);
    }

    @Test
    public void copyStream_oneMoreThanBuffer() throws Exception {
        testCopyStream(IOHelper.BUFFER_SIZE + 1);
    }

    @Test
    public void copyStream_twiceMoreThanBuffer() throws Exception {
        testCopyStream(IOHelper.BUFFER_SIZE * 2);
    }
}
