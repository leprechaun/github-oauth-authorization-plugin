/*
 * Copyright 2017 ThoughtWorks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cd.go.authorization.github.executors;

import cd.go.authorization.github.exceptions.AuthenticationException;
import cd.go.authorization.github.exceptions.NoAuthorizationConfigurationException;
import cd.go.authorization.github.models.AuthConfig;
import cd.go.authorization.github.models.GitHubConfiguration;
import cd.go.authorization.github.models.TokenInfo;
import cd.go.authorization.github.requests.FetchAccessTokenRequest;
import com.thoughtworks.go.plugin.api.response.DefaultGoPluginApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import java.net.Proxy;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import static cd.go.authorization.github.GitHubPlugin.LOG;
import static java.text.MessageFormat.format;
import com.thoughtworks.go.plugin.api.logging.Logger;

public class FetchAccessTokenRequestExecutor implements RequestExecutor {
    private final FetchAccessTokenRequest request;
    private final OkHttpClient httpClient;

    public static final Logger LOG = Logger.getLoggerFor(FetchAccessTokenRequestExecutor.class);

    public FetchAccessTokenRequestExecutor(FetchAccessTokenRequest request) {
        this(request, new OkHttpClient.Builder());
    }

    FetchAccessTokenRequestExecutor(FetchAccessTokenRequest request, OkHttpClient.Builder clientBuilder) {
        if(System.getProperty("https.proxyHost", "") != "") {
          System.out.println(System.getProperty("https.proxyHost"));
          LOG.warn(System.getProperty("https.proxyHost") + ":" + System.getProperty("https.proxyPort"));
          Proxy proxy = new Proxy(
            Proxy.Type.HTTP,
            new InetSocketAddress(
              System.getProperty("https.proxyHost"),
              Integer.parseInt(System.getProperty("https.proxyPort"))
            )
          );
          clientBuilder.proxy(proxy);
        } else {
          LOG.warn("No proxy defined");
        }

        this.request = request;
        this.httpClient = clientBuilder
          .connectTimeout(30, TimeUnit.SECONDS)
          .writeTimeout(30, TimeUnit.SECONDS)
          .readTimeout(30, TimeUnit.SECONDS)
          .build();
    }

    public GoPluginApiResponse execute() throws Exception {
        if (request.authConfigs() == null || request.authConfigs().isEmpty()) {
            throw new NoAuthorizationConfigurationException("[Get Access Token] No authorization configuration found.");
        }

        if (!request.requestParameters().containsKey("code")) {
            throw new IllegalArgumentException("Get Access Token] Expecting `code` in request params, but not received.");
        }

        final AuthConfig authConfig = request.authConfigs().get(0);
        final GitHubConfiguration gitHubConfiguration = authConfig.gitHubConfiguration();

        String fetchAccessTokenUrl = fetchAccessTokenUrl(gitHubConfiguration);
        System.out.println("Token URL:" + fetchAccessTokenUrl);
        final Request fetchAccessTokenRequest = fetchAccessTokenRequest(fetchAccessTokenUrl);

        final Response response = httpClient.newCall(fetchAccessTokenRequest).execute();
        LOG.info("HTTP Message: " + response.message());
        LOG.info("HTTP Body: " + response.body());
        LOG.info("Response" + response.toString());
        if (response.isSuccessful()) {
            LOG.info("[Get Access Token] Access token fetched successfully.");
            final TokenInfo tokenInfo = TokenInfo.fromJSON(response.body().string());
            return DefaultGoPluginApiResponse.success(tokenInfo.toJSON());
        }

        throw new AuthenticationException(format("[Get Access Token] {0}", response.message()));
    }

    private Request fetchAccessTokenRequest(String fetchAccessTokenUrl) {
        return new Request.Builder()
                .url(fetchAccessTokenUrl)
                .addHeader("Accept", "application/json")
                .build();
    }

    private String fetchAccessTokenUrl(GitHubConfiguration gitHubConfiguration) {
        return HttpUrl.parse(gitHubConfiguration.apiUrl())
                .newBuilder()
                .addPathSegment("login")
                .addPathSegment("oauth")
                .addPathSegment("access_token")
                .addQueryParameter("client_id", gitHubConfiguration.clientId())
                .addQueryParameter("client_secret", gitHubConfiguration.clientSecret())
                .addQueryParameter("code", request.requestParameters().get("code"))
                .build().toString();
    }
}
