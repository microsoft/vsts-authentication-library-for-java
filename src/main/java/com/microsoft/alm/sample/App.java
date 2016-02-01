// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See License.txt in the project root.

package com.microsoft.alm.sample;

import com.microsoft.alm.auth.PromptBehavior;
import com.microsoft.alm.auth.pat.VstsPatAuthenticator;
import com.microsoft.alm.auth.secret.Credential;
import com.microsoft.alm.auth.secret.Token;
import com.microsoft.alm.auth.secret.TokenPair;
import com.microsoft.alm.auth.secret.VsoTokenScope;
import com.microsoft.alm.provider.JaxrsClientProvider;
import com.microsoft.alm.provider.Options;
import com.microsoft.alm.provider.UserPasswordCredentialProvider;
import com.microsoft.alm.sourcecontrol.webapi.GitHttpClient;
import com.microsoft.alm.sourcecontrol.webapi.model.GitRepository;
import com.microsoft.alm.storage.InsecureInMemoryStore;
import com.microsoft.alm.storage.SecretStore;
import com.microsoft.visualstudio.services.account.Account;
import com.microsoft.visualstudio.services.account.AccountHttpClient;

import javax.ws.rs.client.Client;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.UUID;

public class App {
    //azure connection settings
    private static final String CLIENT_ID = "502ea21d-e545-4c66-9129-c352ec902969";
    private static final String REDIRECT_URL = "https://xplatalm.com";

    public static void main(String args[]) throws URISyntaxException {
        App app = new App();
        app.intellijFlow();
    }

    public void intellijFlow() {
        // Create the storage for OAuth token and token, if you already have an OAuth store that contains
        // valid OAuth AccessTokens, this is the place to reuse them
        final SecretStore<TokenPair> accessTokenStore = new InsecureInMemoryStore<TokenPair>();
        final SecretStore<Token> tokenStore = new InsecureInMemoryStore<Token>();

        //First create the authenticator
        final VstsPatAuthenticator patAuthenticator = new VstsPatAuthenticator(CLIENT_ID, REDIRECT_URL,
                accessTokenStore, tokenStore);

        //Create a jaxrs client provider with this authenticator
        final JaxrsClientProvider clientProvider = new JaxrsClientProvider(patAuthenticator);

        //Set up options to create PAT in case there is nothing stored
        final Options options = Options.getDefaultOptions();
        options.patGenerationOptions.displayName = "Intellij PAT Testing";
        options.patGenerationOptions.tokenScope = VsoTokenScope.All; // leave it to ALL if we want to manage wit

        // Get a client with global privilege to look up all accounts
        final Client client = clientProvider.getVstsGlobalClient(PromptBehavior.AUTO, options);

        // Get list of accounts
        final AccountHttpClient accountHttpClient
                = new AccountHttpClient(client, URI.create("https://app.vssps.visualstudio.com"));

        UUID myId = accountHttpClient.getMyProfile().getId();
        List<Account> accounts = accountHttpClient.getAccounts(myId);

        // now picked out one account from the list, and assume we cloned it, we should transfer the global PAT
        // to this particular account we cloned
        URI targetAcct = URI.create("https://" + accounts.get(0).getAccountName() + ".visualstudio.com/DefaultCollection");

        // save this pat for the cloned account so we have credential for it
        patAuthenticator.assignGlobalPatTo(targetAcct);

        // Now after awhile we come back to do more with the git url, such as pull request.
        // Should not prompt for credentials since we have transferred the global PAT to this account before
        final Client specificClient = clientProvider.getSpecificClientFor(targetAcct);

        GitHttpClient gitHttpClient = new GitHttpClient(specificClient, targetAcct);
        List<GitRepository> repos = gitHttpClient.getRepositories();
        System.out.println(repos.get(0).getName());

        // You can just create a new PAT authenticator as long as you use the same storage, you should get
        // same PAT without being prompted
        // The accessToken store is not important since accessToken expires in an hour anyway
        final VstsPatAuthenticator newPatAuthenticator = new VstsPatAuthenticator(CLIENT_ID, REDIRECT_URL,
                new InsecureInMemoryStore<TokenPair>(),  // new AccessToken store
                tokenStore); // same persisted token store
        final UserPasswordCredentialProvider passwordCredentialProvider
                = new UserPasswordCredentialProvider(newPatAuthenticator);

        Credential credential = passwordCredentialProvider.getSpecificCredentialFor(targetAcct);

        System.out.println(credential.Username + ":" + credential.Password);

        // switch to another user account
        patAuthenticator.signOutGlobally();

        // Now this should prompt again
        // if no option passed in, we will just generate a PAT with default name
        final Client anotherClient = clientProvider.getVstsGlobalClient();
    }

}
