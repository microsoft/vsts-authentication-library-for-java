// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.storage;

import com.microsoft.alm.helpers.IOHelper;
import com.microsoft.alm.secret.Credential;
import com.microsoft.alm.secret.Token;
import com.microsoft.alm.secret.TokenType;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class InsecureFileBackendTest {

    /**
     * {@link InsecureFileBackend#delete(String)} must not throw an exception for an invalid key,
     * because when entering incorrect credentials, git will issue an "erase" command on an entry
     * that may not actually be there, so we shouldn't panic and instead just calmly carry on.
     */
    @Test
    public void delete_noMatchingTokenOrCredential() {
        final InsecureFileBackend cut = new InsecureFileBackend(null);

        cut.delete("foo");
    }

    @Test
    public void fromXml() {
        ByteArrayInputStream bais = null;
        try {
            final String xmlString =
                    "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n" +
                            "<insecureStore>\n" +
                            "    <Tokens/>\n" +
                            "    <Credentials>\n" +
                            "        <entry>\n" +
                            "            <key>git:https://server.example.com</key>\n" +
                            "            <value>\n" +
                            "                <Password>swordfish</Password>\n" +
                            "                <Username>j.travolta</Username>\n" +
                            "            </value>\n" +
                            "        </entry>\n" +
                            "    </Credentials>\n" +
                            "</insecureStore>";
            bais = new ByteArrayInputStream(xmlString.getBytes());

            final InsecureFileBackend actual = InsecureFileBackend.fromXml(bais);

            Assert.assertNotNull(actual);
            Assert.assertEquals(1, actual.Credentials.size());
            final Credential credential = actual.Credentials.get("git:https://server.example.com");
            Assert.assertEquals("swordfish", credential.Password);
            Assert.assertEquals("j.travolta", credential.Username);
        } finally {
            IOHelper.closeQuietly(bais);
        }
    }

    @Test
    public void serialization_instanceToXmlToInstance() {
        final InsecureFileBackend input = new InsecureFileBackend(null);
        initializeTestData(input);

        final InsecureFileBackend actual = clone(input);

        verifyTestData(actual);
    }


    private static void initializeTestData(final InsecureFileBackend input) {
        final Token inputBravo = new Token("42", TokenType.Test);
        input.writeToken("alpha", null);
        input.writeToken("bravo", inputBravo);
        input.writeCredential("charlie", null);
        final Credential inputDelta = new Credential("douglas.adams", "42");
        input.writeCredential("delta", inputDelta);
    }

    private void verifyTestData(final InsecureFileBackend actual) {
        Assert.assertEquals(2, actual.Tokens.size());
        Assert.assertTrue(actual.Tokens.containsKey("alpha"));
        final Token actualBravo = actual.Tokens.get("bravo");
        Assert.assertEquals("42", actualBravo.Value);
        Assert.assertEquals(TokenType.Test, actualBravo.Type);
        Assert.assertFalse(actual.Tokens.containsKey("charlie"));

        Assert.assertEquals(2, actual.Credentials.size());
        Assert.assertTrue(actual.Credentials.containsKey("charlie"));
        final Credential actualDelta = actual.Credentials.get("delta");
        Assert.assertEquals("douglas.adams", actualDelta.Username);
        Assert.assertEquals("42", actualDelta.Password);
    }

    static InsecureFileBackend clone(InsecureFileBackend inputStore) {
        ByteArrayOutputStream baos = null;
        ByteArrayInputStream bais = null;
        try {
            baos = new ByteArrayOutputStream();

            inputStore.toXml(baos);

            final String xmlString = baos.toString();

            bais = new ByteArrayInputStream(xmlString.getBytes());

            return InsecureFileBackend.fromXml(bais);
        } finally {
            IOHelper.closeQuietly(baos);
            IOHelper.closeQuietly(bais);
        }
    }
}