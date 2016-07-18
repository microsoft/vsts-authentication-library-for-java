// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.secret;

import com.microsoft.alm.helpers.Debug;
import com.microsoft.alm.helpers.PropertyBag;
import com.microsoft.alm.helpers.StringHelper;
import com.microsoft.alm.helpers.XmlHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class TokenPair extends Secret {
    private static final Map<String, String> EMPTY_MAP = Collections.unmodifiableMap(new LinkedHashMap<String, String>(0));
    private static final String ACCESS_TOKEN = "access_token";
    private static final String REFRESH_TOKEN = "refresh_token";

    /**
     * Creates a new {@link TokenPair} from raw access and refresh token data.
     *
     * @param accessToken  The base64 encoded value of the access token's raw data
     * @param refreshToken The base64 encoded value of the refresh token's raw data
     */
    public TokenPair(final String accessToken, final String refreshToken) {
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(accessToken), "The accessToken parameter is null or invalid.");
        Debug.Assert(!StringHelper.isNullOrWhiteSpace(refreshToken), "The refreshToken parameter is null or invalid.");

        this.AccessToken = new Token(accessToken, TokenType.Access);
        this.RefreshToken = new Token(refreshToken, TokenType.Refresh);
        this.Parameters = EMPTY_MAP;
    }

    public TokenPair(final String accessTokenResponse) {
        this(PropertyBag.fromJson(accessTokenResponse));
    }

    public TokenPair(final PropertyBag bag) {
        final LinkedHashMap<String, String> parameters = new LinkedHashMap<String, String>();
        String accessToken = null;
        String refreshToken = null;
        for (final Map.Entry<String, Object> pair : bag.entrySet()) {
            final String name = pair.getKey();
            final Object value = pair.getValue();
            if (ACCESS_TOKEN.equals(name)) {
                accessToken = (String) value;
            }
            else if (REFRESH_TOKEN.equals(name)) {
                refreshToken = (String) value;
            }
            else {
                parameters.put(name, value.toString());
            }

        }
        this.AccessToken = new Token(accessToken, TokenType.Access);
        this.RefreshToken = new Token(refreshToken, TokenType.Refresh);
        this.Parameters = Collections.unmodifiableMap(parameters);
    }

    /**
     * Access token, used to grant access to resources.
     */
    public final Token AccessToken;
    /**
     * Refresh token, used to grant new access tokens.
     */
    public final Token RefreshToken;
    public final Map<String, String> Parameters;

    public static TokenPair fromXml(final Node tokenPairNode) {
        TokenPair value;

        String accessToken = null;
        String refreshToken = null;

        final NodeList propertyNodes = tokenPairNode.getChildNodes();
        for (int v = 0; v < propertyNodes.getLength(); v++) {
            final Node propertyNode = propertyNodes.item(v);
            final String propertyName = propertyNode.getNodeName();
            if ("accessToken".equals(propertyName)) {
                accessToken = XmlHelper.getText(propertyNode);
            } else if ("refreshToken".equals(propertyName)) {
                refreshToken = XmlHelper.getText(propertyNode);
            }
        }

        value = new TokenPair(accessToken, refreshToken);
        return value;
    }

    public Element toXml(final Document document) {
        final Element valueNode = document.createElement("value");

        final Element accessTokenNode = document.createElement("accessToken");
        final Text accessTokenValue = document.createTextNode(AccessToken.Value);
        accessTokenNode.appendChild(accessTokenValue);
        valueNode.appendChild(accessTokenNode);

        final Element refreshTokenNode = document.createElement("refreshToken");
        final Text refreshTokenValue = document.createTextNode(RefreshToken.Value);
        refreshTokenNode.appendChild(refreshTokenValue);
        valueNode.appendChild(refreshTokenNode);

        return valueNode;
    }

    public static String toXmlString(final TokenPair tokenPair) {
        final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = dbf.newDocumentBuilder();
            final Document document = builder.newDocument();

            final Element element = tokenPair.toXml(document);
            document.appendChild(element);

            final String result = XmlHelper.toString(document);

            return result;
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    public static TokenPair fromXmlString(final String xmlString) {
        final byte[] bytes = StringHelper.UTF8GetBytes(xmlString);
        final ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
        return fromXmlStream(inputStream);
    }

    static TokenPair fromXmlStream(final InputStream source) {
        final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        try {
            final DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
            final Document document = builder.parse(source);
            final Element rootElement = document.getDocumentElement();

            final TokenPair result = TokenPair.fromXml(rootElement);

            return result;
        }
        catch (final Exception e) {
            throw new Error(e);
        }
    }

    /**
     * Compares an object to this.
     *
     * @param object The object to compare.
     * @return True if equal; false otherwise
     */
    @Override
    public boolean equals(final Object object) {
        return operatorEquals(this, object instanceof TokenPair ? ((TokenPair) object) : null);
    }
    // PORT NOTE: Java doesn't support a specific overload (as per IEquatable<T>)

    /**
     * Gets a hash code based on the contents of the {@link TokenPair}.
     *
     * @return 32-bit hash code.
     */
    @Override
    public int hashCode() {
        // PORT NOTE: Java doesn't have unchecked blocks; the default behaviour is apparently equivalent.
        {
            return AccessToken.hashCode() * RefreshToken.hashCode();
        }
    }

    /**
     * Compares two {@link TokenPair} for equality.
     *
     * @param pair1 {@link TokenPair} to compare.
     * @param pair2 {@link TokenPair} to compare.
     * @return True if equal; false otherwise.
     */
    public static boolean operatorEquals(final TokenPair pair1, final TokenPair pair2) {
        if (pair1 == pair2)
            return true;
        if ((pair1 == null) || (null == pair2))
            return false;

        return Token.operatorEquals(pair1.AccessToken, pair2.AccessToken)
                && Token.operatorEquals(pair1.RefreshToken, pair2.RefreshToken);
    }

    /**
     * Compares two {@link TokenPair} for inequality.
     *
     * @param pair1 {@link TokenPair} to compare.
     * @param pair2 {@link TokenPair} to compare.
     * @return False if equal; true otherwise.
     */
    public static boolean operatorNotEquals(final TokenPair pair1, final TokenPair pair2) {
        return !operatorEquals(pair1, pair2);
    }
}
