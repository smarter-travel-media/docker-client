/*-
 * -\-\-
 * docker-client
 * --
 * Copyright (C) 2018 Smarter Travel Media LLC
 * --
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -/-/-
 */

package com.spotify.docker.client.auth.ecr;

import com.amazonaws.services.ecr.AmazonECR;
import com.amazonaws.services.ecr.model.AuthorizationData;
import com.amazonaws.services.ecr.model.GetAuthorizationTokenRequest;
import com.amazonaws.services.ecr.model.GetAuthorizationTokenResult;
import com.amazonaws.services.ecr.model.InvalidParameterException;
import com.amazonaws.services.ecr.model.ServerException;
import com.amazonaws.util.Base64;
import com.spotify.docker.client.ImageRef;
import com.spotify.docker.client.auth.RegistryAuthSupplier;
import com.spotify.docker.client.exceptions.DockerException;
import com.spotify.docker.client.messages.RegistryAuth;
import com.spotify.docker.client.messages.RegistryConfigs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Implementation of a {@link RegistryAuthSupplier} that authenticates with Amazon
 * Elastic Container Repository (ECR) using a provided {@link AmazonECR} client.
 */
public class AwsEcrRegistryAuthSupplier implements RegistryAuthSupplier {

  private static final Logger log = LoggerFactory.getLogger(AwsEcrRegistryAuthSupplier.class);

  private final static String ECR_DOMAIN = ".amazonaws.com";
  private final AmazonECR client;
  private final Base64Decoder decoder;
  private final Sleep sleep;
  private final long retryBackoffMillis;
  private final int maxRetries;

  private AwsEcrRegistryAuthSupplier(Builder builder) {
    this.client = builder.getClient();
    this.decoder = builder.getDecoder();
    this.sleep = builder.getSleep();
    this.retryBackoffMillis = builder.getRetryBackoffMillis();
    this.maxRetries = builder.getMaxRetries();
  }

  /**
   * @return A new builder for constructing AWS ECR auth suppliers
   */
  public static Builder builder() {
    return new Builder();
  }

  private RegistryAuth authForRegistryId(@Nullable String registryId) throws DockerException {
    final GetAuthorizationTokenRequest request = new GetAuthorizationTokenRequest();
    if (registryId != null) {
      request.setRegistryIds(Collections.singleton(registryId));
    }

    final GetAuthorizationTokenResult response;
    try {
      response = getTokenWithRetries(request);
    } catch (ServerException | InvalidParameterException e) {
      throw new DockerException(e);
    }

    final List<AuthorizationData> auths = response.getAuthorizationData();
    if (auths == null || auths.size() != 1) {
      throw new DockerException("" +
        "Didn't get expected number of AuthorizationData results from ECR. Expected 1 " +
        "item but instead got " + (auths == null ? "[null]" : String.valueOf(auths.size())) +
        ". Tried to fetch authorization for registry ID '" + registryId + "'."
      );
    }

    return parseAuthorizationData(auths.get(0));
  }

  private GetAuthorizationTokenResult getTokenWithRetries(GetAuthorizationTokenRequest request) {
    int retries = 0;

    while (true) {
      try {
        return client.getAuthorizationToken(request);
      } catch (ServerException e) {
        if (retries >= maxRetries) {
          throw e;
        }

        log.debug("Sleeping for {} ms before retry because of  server error fetching  ECR " +
          "token: {}", retryBackoffMillis, e.getMessage());
        sleep.sleepMs(retryBackoffMillis);
        retries += 1;
      }
    }
  }

  private RegistryAuth parseAuthorizationData(AuthorizationData data) throws DockerException {
    final String endpoint = data.getProxyEndpoint();
    final String base64 = data.getAuthorizationToken();
    final String decoded = decoder.decode(base64);
    if (decoded == null) {
      throw new DockerException("Unexpected null authorization token for endpoint '" + endpoint + "'");
    }

    // The token is a base64 encoded string of the format "user:password".
    final int userPasswordIndex = decoded.indexOf(':');
    if (userPasswordIndex == -1) {
      throw new DockerException("Invalid format for authorization token for endpoint '" + endpoint + "'");
    }

    final String username = decoded.substring(0, userPasswordIndex);
    final String password = decoded.substring(userPasswordIndex + 1 /* +1 for the ':' itself */, decoded.length());

    return RegistryAuth.builder()
      .username(username)
      .password(password)
      .serverAddress(endpoint)
      .build();
  }

  private static boolean isEcrImage(ImageRef image) {
    final String registry = image.getRegistryName();
    return registry.endsWith(ECR_DOMAIN);
  }

  /**
   * Get the AWS account ID from the provided image which will be used when requesting
   * authorization for a particular image (such as with {@link #authFor(String)}).
   * <p>
   * See https://docs.aws.amazon.com/AmazonECR/latest/userguide/Registries.html
   */
  private static String parseAccountIdFromImage(ImageRef image) throws DockerException {
    final String registryName = image.getRegistryName();
    final int subdomainIndex = registryName.indexOf('.');
    if (subdomainIndex == -1) {
      throw new DockerException("Could not parse AWS account ID from registry host " + registryName);
    }

    return registryName.substring(0, subdomainIndex);
  }

  /**
   * Get the host name and optional port of the provided server address.
   * <p>
   * This is used when constructing a RegistryConfigs instance mapping registry names to
   * the associated authentication information. Port is omitted when the original server
   * endpoint associated with the auth information doesn't include a port or when the port
   * is the default (HTTPS, 443).
   * <p>
   * See https://docs.docker.com/engine/api/v1.37/#section/Authentication
   */
  private static String getRegistryName(URI serverAddress) {
    final int port = serverAddress.getPort();
    if (port == -1 || port == 443) {
      return serverAddress.getHost();
    }

    return serverAddress.getHost() + ":" + port;
  }

  @Override
  public RegistryAuth authFor(String imageName) throws DockerException {
    final ImageRef image = new ImageRef(imageName);
    if (!isEcrImage(image)) {
      return null;
    }

    final String registryId = parseAccountIdFromImage(image);
    return authForRegistryId(registryId);
  }

  @Override
  public RegistryAuth authForSwarm() throws DockerException {
    try {
      return authForRegistryId(null);
    } catch (DockerException e) {
      log.warn("Unable to get authentication data for AWS ECR registry, "
        + "configuration for Swarm will not contain registry auth for ECR", e);
      return null;
    }
  }

  @Override
  public RegistryConfigs authForBuild() throws DockerException {
    final RegistryAuth auth;

    try {
      auth = authForRegistryId(null);
    } catch (DockerException e) {
      log.warn("Unable to get authentication data for AWS ECR registry, "
        + "configuration for building images will not contain RegistryAuth for ECR", e);
      return RegistryConfigs.empty();
    }

    final URI serverAddress;
    try {
      serverAddress = new URI(auth.serverAddress());
    } catch (URISyntaxException e) {
      log.warn("Unable to parse server URL for AWS ECR registry, "
        + "configuration for building images will not contain RegistryAuth for ECR", e);
      return RegistryConfigs.empty();
    }

    final String registryName = getRegistryName(serverAddress);
    final Map<String, RegistryAuth> configs = Collections.singletonMap(registryName, auth);
    return RegistryConfigs.create(configs);
  }


  /**
   * Builder for creating a new immutable {@link AwsEcrRegistryAuthSupplier} instance.
   * <p>
   * All values except the {@link AmazonECR} client are optional and will use reasonable defaults
   * if not supplied.
   */
  public static class Builder {
    private AmazonECR client;
    private Base64Decoder decoder = DefaultBase64Decoder.getInstance();
    private Sleep sleep = DefaultSleep.getInstance();
    private long retryBackoffMillis = 50;
    private int maxRetries = 1;

    /**
     * @return The ECR client to use
     */
    public AmazonECR getClient() {
      return client;
    }

    /**
     * @param client The AWS ECR client to use
     */
    public void setClient(AmazonECR client) {
      this.client = client;
    }

    /**
     * @param client The AWS ECR client to use
     * @return fluent interface
     */
    public Builder withClient(AmazonECR client) {
      setClient(client);
      return this;
    }

    /**
     * @return The base 64 decoder to use
     */
    public Base64Decoder getDecoder() {
      return decoder;
    }

    /**
     * @param decoder The base 64 decoder to use
     */
    public void setDecoder(Base64Decoder decoder) {
      this.decoder = decoder;
    }

    /**
     * @param decoder The base 64 decoder to use
     * @return fluent interface
     */
    public Builder withDecoder(Base64Decoder decoder) {
      setDecoder(decoder);
      return this;
    }

    /**
     * @return The Sleep implementation to use (only used for unit tests).
     */
    public Sleep getSleep() {
      return sleep;
    }

    /**
     * @param sleep The Sleep implementation to use (only used for unit tests).
     */
    public void setSleep(Sleep sleep) {
      this.sleep = sleep;
    }

    /**
     * @param sleep The Sleep implementation to use (only used for unit tests).
     * @return fluent interface
     */
    public Builder withSleep(Sleep sleep) {
      setSleep(sleep);
      return this;
    }

    /**
     * @return The number of milliseconds to wait between retries after server errors.
     */
    public long getRetryBackoffMillis() {
      return retryBackoffMillis;
    }

    /**
     * @param retryBackoffMillis The number of milliseconds to wait between retries after server errors
     */
    public void setRetryBackoffMillis(long retryBackoffMillis) {
      this.retryBackoffMillis = retryBackoffMillis;
    }

    /**
     * @param retryBackoffMillis The number of milliseconds to wait between retries after server errors
     * @return fluent interface
     */
    public Builder withRetryBackoffMillis(long retryBackoffMillis) {
      setRetryBackoffMillis(retryBackoffMillis);
      return this;
    }

    /**
     * @return The max number of retries that will be attempted after an initial request (default 1)
     */
    public int getMaxRetries() {
      return maxRetries;
    }

    /**
     * @param maxRetries The max number of retries that will be attempted after an initial request (default 1)
     */
    public void setMaxRetries(int maxRetries) {
      this.maxRetries = maxRetries;
    }

    /**
     * @param maxRetries The max number of retries that will be attempted after an initial request (default 1)
     * @return fluent interface
     */
    public Builder withMaxRetries(int maxRetries) {
      setMaxRetries(maxRetries);
      return this;
    }

    /**
     * @return New immutable {@link AwsEcrRegistryAuthSupplier} using to configured values.
     */
    public AwsEcrRegistryAuthSupplier build() {
      return new AwsEcrRegistryAuthSupplier(this);
    }
  }

  /**
   * Interface to make testing code that calls time-related functions easier
   */
  public interface Sleep {
    void sleepMs(long millis);
  }

  /**
   * Default implementation of the {@link Sleep} interface that calls concrete JDK methods
   * to actually sleep. This is what is desired in most cases, except during unit tests.
   */
  public static class DefaultSleep implements Sleep {

    private static final DefaultSleep INSTANCE = new DefaultSleep();

    public static DefaultSleep getInstance() {
      return INSTANCE;
    }

    @Override
    public void sleepMs(long millis) {
      try {
        Thread.sleep(millis);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
  }

  /**
   * Interface for decoding base 64 text into a plain-text string
   */
  public interface Base64Decoder {
    String decode(String encoded);
  }

  /**
   * Implementation of the {@link Base64Decoder} interface that delegates to the AWS SDK
   * base 64 decoder.
   */
  public static class DefaultBase64Decoder implements Base64Decoder {

    private static final DefaultBase64Decoder INSTANCE = new DefaultBase64Decoder();

    public static DefaultBase64Decoder getInstance() {
      return INSTANCE;
    }

    @Override
    public String decode(String encoded) {
      final byte[] res = Base64.decode(encoded);
      if (res == null) {
        return null;
      }
      return new String(res, StandardCharsets.US_ASCII);
    }
  }
}
