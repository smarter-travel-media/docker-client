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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

import com.amazonaws.services.ecr.AmazonECR;
import com.amazonaws.services.ecr.model.AuthorizationData;
import com.amazonaws.services.ecr.model.GetAuthorizationTokenRequest;
import com.amazonaws.services.ecr.model.GetAuthorizationTokenResult;
import com.amazonaws.services.ecr.model.InvalidParameterException;
import com.amazonaws.services.ecr.model.ServerException;
import com.spotify.docker.client.auth.ecr.AwsEcrRegistryAuthSupplier.Sleep;
import com.spotify.docker.client.exceptions.DockerException;
import com.spotify.docker.client.messages.RegistryAuth;
import com.spotify.docker.client.messages.RegistryConfigs;
import java.util.concurrent.atomic.AtomicLong;
import org.joda.time.Instant;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class AwsEcrRegistryAuthSupplierTest {

  private static final AuthorizationData GOOD_AUTH;

  private static final AuthorizationData NULL_AUTH;

  private static final AuthorizationData BAD_AUTH;

  static {
    GOOD_AUTH = new AuthorizationData()
        .withAuthorizationToken("QVdTOnNvbWVwYXNzd29yZA==") // "AWS:somepassword"
        .withExpiresAt(Instant.now().plus(3600 * 1000 * 12).toDate())
        .withProxyEndpoint("https://12345.dkr.ecr.us-east-1.amazonaws.com/");

    NULL_AUTH = new AuthorizationData()
        .withAuthorizationToken(null)
        .withExpiresAt(Instant.now().plus(3600 * 1000 * 12).toDate())
        .withProxyEndpoint("https://12345.dkr.ecr.us-east-1.amazonaws.com/");

    BAD_AUTH = new AuthorizationData()
        .withAuthorizationToken("aW52YWxpZA==") // "invalid"
        .withExpiresAt(Instant.now().plus(3600 * 1000 * 12).toDate())
        .withProxyEndpoint("https://12345.dkr.ecr.us-east-1.amazonaws.com/");
  }

  @Mock
  private AmazonECR client;

  @Test
  public void testAuthForNonEcrImage() throws DockerException {
    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    final RegistryAuth auth1 = supplier.authFor("team/project:latest");
    assertNull(auth1);

    final RegistryAuth auth2 = supplier.authFor("index.docker.io/team/project:1.3.4");
    assertNull(auth2);
  }

  @Test
  public void testAuthForSuccessNoRetries() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult()
        .withAuthorizationData(GOOD_AUTH);

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class))).thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    final RegistryAuth auth = supplier.authFor(
        "12345.dkr.ecr.us-east-1.amazonaws.com/team/project:latest");
    assertEquals("AWS", auth.username());
    assertEquals("somepassword", auth.password());
    assertEquals("https://12345.dkr.ecr.us-east-1.amazonaws.com/", auth.serverAddress());
  }

  @Test
  public void testAuthForSuccessOneRetry() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult()
        .withAuthorizationData(GOOD_AUTH);

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenThrow(new ServerException("Service unavailable"))
        .thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .withMaxRetries(1)
        .build();

    final RegistryAuth auth = supplier.authFor(
        "12345.dkr.ecr.us-east-1.amazonaws.com/team/project:latest");
    assertEquals("AWS", auth.username());
    assertEquals("somepassword", auth.password());
    assertEquals("https://12345.dkr.ecr.us-east-1.amazonaws.com/", auth.serverAddress());
  }

  @Test(expected = DockerException.class)
  public void testAuthForServerException() throws DockerException {
    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenThrow(new ServerException("Service unavailable"));

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .withMaxRetries(1)
        .build();

    supplier.authFor("67890.dkr.ecr.us-west-2.amazonaws.com/team/project:latest");
  }

  @Test(expected = DockerException.class)
  public void testAuthForParameterException() throws DockerException {
    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenThrow(new InvalidParameterException("Bad parameters"));

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    supplier.authFor("12345.dkr.ecr.us-east-1.amazonaws.com/team/project:1.2.3");
  }

  @Test(expected = DockerException.class)
  public void testAuthForNoResults() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult();

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class))).thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    supplier.authFor("12345.dkr.ecr.us-east-1.amazonaws.com/team/project:latest");
  }

  @Test(expected = DockerException.class)
  public void testAuthForNullAuthorizationData() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult()
        .withAuthorizationData(NULL_AUTH);

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    supplier.authFor("12345.dkr.ecr.us-east-1.amazonaws.com/team/project:1.2.3");
  }

  @Test(expected = DockerException.class)
  public void testAuthForMalformedAuthorizationData() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult()
        .withAuthorizationData(BAD_AUTH);

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    supplier.authFor("12345.dkr.ecr.us-east-1.amazonaws.com/team/project:latest");
  }

  @Test
  public void testAuthForSwarm() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult()
        .withAuthorizationData(GOOD_AUTH);

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    final RegistryAuth auth = supplier.authForSwarm();
    assertEquals("AWS", auth.username());
    assertEquals("somepassword", auth.password());
    assertEquals("https://12345.dkr.ecr.us-east-1.amazonaws.com/", auth.serverAddress());
  }

  @Test
  public void testAuthForSwarmFailure() throws DockerException {
    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenThrow(new ServerException("Service unavailable"));

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    final RegistryAuth auth = supplier.authForSwarm();
    assertNull(auth);
  }

  @Test
  public void testAuthForBuild() throws DockerException {
    final GetAuthorizationTokenResult result = new GetAuthorizationTokenResult()
        .withAuthorizationData(GOOD_AUTH);

    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenReturn(result);

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    final RegistryConfigs configs = supplier.authForBuild();
    final RegistryAuth auth = configs.configs().get("12345.dkr.ecr.us-east-1.amazonaws.com");

    assertNotNull(auth);
    assertEquals("AWS", auth.username());
    assertEquals("somepassword", auth.password());
    assertEquals("https://12345.dkr.ecr.us-east-1.amazonaws.com/", auth.serverAddress());
  }

  @Test
  public void testAuthForBuildFailure() throws DockerException {
    when(client.getAuthorizationToken(any(GetAuthorizationTokenRequest.class)))
        .thenThrow(new ServerException("Service unavailable"));

    final FakeSleep sleep = new FakeSleep();
    final AwsEcrRegistryAuthSupplier supplier = AwsEcrRegistryAuthSupplier.builder()
        .withClient(client)
        .withSleep(sleep)
        .build();

    final RegistryConfigs configs = supplier.authForBuild();
    assertTrue(configs.configs().isEmpty());
  }

  static class FakeSleep implements Sleep {

    private final AtomicLong slept = new AtomicLong(0);

    @Override
    public void sleepMs(long millis) {
      slept.addAndGet(millis);
    }
  }

}
