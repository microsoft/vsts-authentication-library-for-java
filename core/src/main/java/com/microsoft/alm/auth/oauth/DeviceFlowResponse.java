// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.auth.oauth;

import com.microsoft.alm.common.helpers.PropertyBag;

import java.net.URI;
import java.util.Calendar;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Represents the result of requesting device flow authorization from a Device Endpoint.
 *
 * @see "Section 3.1 Client Requests Authorization"
 */
public class DeviceFlowResponse {

    /**
     * WAITING_FOR_USER:
     *      This library will continue issue server calls to poll for authentication result
     *
     * CANCEL_REQUESTED:
     *      This library will stop making server calls and give up on creating a token with device flow
     *
     * TOKEN_ACQUIRED:
     *      This library has received an OAuth2 Token based on Device Flow
     */
    enum RESPONSE_STATE {
        WAITING_FOR_USER,
        CANCEL_REQUESTED,
        TOKEN_ACQUIRED
    }

    private final AtomicReference<RESPONSE_STATE> state = new AtomicReference<RESPONSE_STATE>();

    private final String deviceCode;
    private final String userCode;
    private final URI verificationUri;
    private final int expiresIn;
    private final Calendar expiresAt;
    private final int interval;

    public DeviceFlowResponse(final String deviceCode, final String userCode, final URI verificationUri, final int expiresIn, final int interval) {
        this.deviceCode = deviceCode;
        this.userCode = userCode;
        this.verificationUri = verificationUri;
        this.expiresIn = expiresIn;
        this.expiresAt = Calendar.getInstance();
        expiresAt.add(Calendar.SECOND, expiresIn);
        this.interval = interval;

        this.state.set(RESPONSE_STATE.WAITING_FOR_USER);
    }

    public static DeviceFlowResponse fromJson(final String jsonText) {
        final PropertyBag bag = PropertyBag.fromJson(jsonText);
        final String deviceCode = (String) bag.get(OAuthParameter.DEVICE_CODE);
        final String userCode = (String) bag.get(OAuthParameter.USER_CODE);
        final String verificationUriString = (String) bag.get(OAuthParameter.VERIFICATION_URI);
        final URI verificationUri = URI.create(verificationUriString);
        final int expiresInSeconds = bag.readOptionalInteger(OAuthParameter.EXPIRES_IN, 600);
        final int intervalInSeconds = bag.readOptionalInteger(OAuthParameter.INTERVAL, 5);

        final DeviceFlowResponse result = new DeviceFlowResponse(deviceCode, userCode, verificationUri, expiresInSeconds, intervalInSeconds);
        return result;
    }

    /**
     * The "Device Verification Code" is defined as
     * "A short-lived token representing an authorization session."
     * in section 2.
     *
     * @return a string that is to be supplied to the token endpoint.
     */
    public String getDeviceCode() {
        return deviceCode;
    }

    /**
     * The "End-User Verification Code" is defined as
     * "A short-lived token which the device displays to the end user, is
     * entered by the end-user on the authorization sever, and is thus
     * used to bind the device to the end-user."
     * in section 2.
     *
     * @return a string that the resource owner (end-user)
     *         will type into the user-agent (web browser)
     *         to link their authentication and authorization
     *         with the device.
     */
    public String getUserCode() {
        return userCode;
    }

    /**
     * The end-user verification URI on the authorization
     * server.  The URI should be short and easy to remember as end-
     * users will be asked to manually type it into their user-agent.
     *
     * @return the URI that the resource owner (end-user)
     *         will visit with their user-agent (web browser)
     *         to complete the device flow process.
     */
    public URI getVerificationUri() {
        return verificationUri;
    }

    /**
     * The duration in seconds of the verification code
     * lifetime.
     *
     * @return the number of seconds the resource owner (end-user)
     *         has to complete the device flow process.
     *
     */
    public int getExpiresIn() {
        return expiresIn;
    }

    /**
     * The date and time when the verification code will
     * no longer be valid.
     *
     * @return a Calendar representing the instant when the
     *         resource owner (end-user) will no longer be
     *         able to complete the device flow process.
     *
     */
    public Calendar getExpiresAt() {
        return expiresAt;
    }

    /**
     * The minimum amount of time in seconds that the client
     * SHOULD wait between polling requests to the token endpoint.
     *
     * @return the minimum number of seconds the client (application)
     *         waits before polling the token endpoint.
     */
    public int getInterval() {
        return interval;
    }

    /**********************************************************************************************
     * Callback flow controls
     **********************************************************************************************/
    /**
     * The library will use this method to determine if it should give up polling for login result.
     *
     * @return true if user has requested to cancel this login session explicitly.
     */
    boolean cancelRequestedByUser() {
        return this.state.get() == RESPONSE_STATE.CANCEL_REQUESTED;
    }

    /**
     * The library will call this method after it successfully acquired the token.
     */
    void setTokenAcquired() {
        this.state.set(RESPONSE_STATE.TOKEN_ACQUIRED);
    }

    /**
     * Callback can monitor this value and react appropriately.  For example, a GUI callback dialog can dispose
     * itself once it realizes the token has been acquired.
     *
     * WARNING: make sure the device flow callback does not block the thread this authentication library is running on.
     * Otherwise the library will not start polling and this value will never be set.
     *
     * @return true if library has successfully acquired the token.
     */
    public boolean isTokenAcquired() {
        return this.state.get() == RESPONSE_STATE.TOKEN_ACQUIRED;
    }

    /**
     * This method is used by the callback to indicate user has given up, and we should
     * stop polling for result.
     *
     * This is a best effort operation.  User may already logged in.
     */
    public void requestCancel() {
        this.state.set(RESPONSE_STATE.CANCEL_REQUESTED);
    }
}
