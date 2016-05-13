// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.secret;

import org.junit.Test;

public class TokenTest {

    @Test(expected = IllegalArgumentException.class)
    public void validate_tooLong() {
        final int numberOfCharacters = 2048;
        final StringBuilder sb = new StringBuilder(numberOfCharacters);
        for (int c = 0; c < numberOfCharacters; c++) {
            sb.append('0');
        }
        final Token token = new Token(sb.toString(), TokenType.Test);

        Token.validate(token);
    }
}
