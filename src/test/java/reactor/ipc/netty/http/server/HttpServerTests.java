/*
 * Copyright (c) 2011-2017 Pivotal Software Inc, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package reactor.ipc.netty.http.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.net.ssl.SSLException;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.DefaultHttpContent;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.util.ResourceLeakDetector;
import org.junit.Ignore;
import org.junit.Test;
import org.testng.Assert;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.ipc.netty.ByteBufFlux;
import reactor.ipc.netty.Connection;
import reactor.ipc.netty.DisposableChannel;
import reactor.ipc.netty.NettyOutbound;
import reactor.ipc.netty.http.HttpResources;
import reactor.ipc.netty.http.client.HttpClient;
import reactor.ipc.netty.http.client.HttpClientResponse;
import reactor.ipc.netty.resources.PoolResources;
import reactor.ipc.netty.tcp.TcpClient;
import reactor.test.StepVerifier;
import reactor.util.function.Tuple2;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Stephane Maldini
 */
public class HttpServerTests {
	@Test public void test() {}
/*

	@Test
	@Ignore
	public void defaultHttpPort() {
		Connection blockingFacade = HttpServer.create()
		                                      .handler((req, resp) -> resp.sendNotFound())
		                                      .wiretap()
		                                      .bindNow();
		blockingFacade.disposeNow();

		assertThat(blockingFacade.address().getPort())
				.isEqualTo(8080);
	}

	@Test
	@Ignore
	public void defaultHttpPortWithAddress() {
		Connection blockingFacade = HttpServer.create()
		                                      .tcpConfiguration(tcpServer -> tcpServer.host("localhost"))
		                                      .handler((req, resp) -> resp.sendNotFound())
		                                      .wiretap()
		                                      .bindNow();
		blockingFacade.disposeNow();

		assertThat(blockingFacade.address().getPort())
				.isEqualTo(8080);
	}

	@Test
	public void releaseInboundChannelOnNonKeepAliveRequest() throws Exception {
		ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);

		Connection c = HttpServer.create()
		                         .port(0)
		                         .handler((req, resp) -> resp.status(200).send())
		                         .wiretap()
		                         .bindNow();

		Flux<ByteBuf> src = Flux.range(0, 3)
		                        .map(n -> Unpooled.wrappedBuffer(Integer.toString(n)
		                                                                .getBytes()));

		Flux.range(0, 100)
		    .concatMap(n -> HttpClient.create(c.address()
		                                       .getPort())
		                              .post("/return",
				                              r -> r.keepAlive(false)
				                                    .send(src))
		                              .map(resp -> {
			                              resp.dispose();
			                              return resp.status()
			                                         .code();
		                              }))
		    .collectList()
		    .block();

		c.dispose();
	}

	@Test
	public void sendFileSecure()
			throws CertificateException, SSLException, URISyntaxException {
		Path largeFile = Paths.get(getClass().getResource("/largeFile.txt").toURI());
		SelfSignedCertificate ssc = new SelfSignedCertificate();
		SslContext sslServer = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey()).build();
		SslContext sslClient = SslContextBuilder.forClient().trustManager(ssc.cert()).build();

		Connection context =
				HttpServer.create()
				          .tcpConfiguration(tcpServer -> tcpServer.secure(sslServer))
				          .handler((req, resp) -> resp.sendFile(largeFile))
				          .wiretap()
				          .bindNow();


		HttpClientResponse response =
				HttpClient.create(opt -> opt.port(context.address().getPort())
				                            .sslContext(sslClient))
				          .get("/foo")
				          .block(Duration.ofSeconds(120));

		context.dispose();
		context.onDispose().block();

		String body = response.receive().aggregate().asString(StandardCharsets.UTF_8).block();

		assertThat(body)
				.startsWith("This is an UTF-8 file that is larger than 1024 bytes. " + "It contains accents like é.")
				.contains("1024 mark here -><- 1024 mark here")
				.endsWith("End of File");
	}

	@Test
	public void sendFileChunked() throws IOException, URISyntaxException {
		Path largeFile = Paths.get(getClass().getResource("/largeFile.txt").toURI());
		long fileSize = Files.size(largeFile);
		assertSendFile(out -> out.sendFileChunked(largeFile, 0, fileSize));
	}

	@Test
	public void sendZipFileChunked() throws IOException {
		Path path = Files.createTempFile(null, ".zip");
		Files.copy(this.getClass().getResourceAsStream("/zipFile.zip"), path, StandardCopyOption.REPLACE_EXISTING);
		path.toFile().deleteOnExit();

		try (FileSystem zipFs = FileSystems.newFileSystem(path, null)) {
			Path fromZipFile = zipFs.getPath("/largeFile.txt");
			long fileSize = Files.size(fromZipFile);
			assertSendFile(out -> out.sendFileChunked(fromZipFile, 0, fileSize));
		}
	}

	@Test
	public void sendZipFileDefault()
			throws IOException {
		Path path = Files.createTempFile(null, ".zip");
		Files.copy(this.getClass().getResourceAsStream("/zipFile.zip"), path, StandardCopyOption.REPLACE_EXISTING);

		try (FileSystem zipFs = FileSystems.newFileSystem(path, null)) {
			Path fromZipFile = zipFs.getPath("/largeFile.txt");
			long fileSize = Files.size(fromZipFile);

			assertSendFile(out -> out.sendFile(fromZipFile, 0, fileSize));
		}
	}

	private void assertSendFile(Function<HttpServerResponse, NettyOutbound> fn) {
		Connection context =
				HttpServer.create()
				          .tcpConfiguration(tcpServer -> tcpServer.host("localhost"))
				          .handler((req, resp) -> fn.apply(resp))
				          .wiretap()
				          .bindNow();


		HttpClientResponse response =
				HttpClient.create(opt -> opt.connectAddress(() -> context.address()))
				          .get("/foo")
				          .block(Duration.ofSeconds(120));

		context.dispose();
		context.onDispose().block();

		String body = response.receive().aggregate().asString(StandardCharsets.UTF_8).block();

		assertThat(body)
				.startsWith("This is an UTF-8 file that is larger than 1024 bytes. " + "It contains accents like é.")
				.contains("1024 mark here -><- 1024 mark here")
				.endsWith("End of File");
	}

	//from https://github.com/reactor/reactor-netty/issues/90
	@Test
	public void testRestart() {
		// start a first server with a handler that answers HTTP 200 OK
		Connection context = HttpServer.create()
		                               .port(8080)
		                               .handler((req, resp) -> resp.status(200)
		                                                                .send().log())
		                               .wiretap()
		                               .bindNow();

		HttpClientResponse response = HttpClient.create(8080).get("/").block();

		// checking the response status, OK
		assertThat(response.status().code()).isEqualTo(200);
		// dispose the Netty context and wait for the channel close
		response.dispose();
		context.dispose();
		context.onDispose().block();

		//REQUIRED - bug pool does not detect/translate properly lifecycle
		HttpResources.reset();

		// create a totally new server instance, with a different handler that answers HTTP 201
		context = HttpServer.create()
		                    .port(8080)
		                    .handler((req, resp) -> resp.status(201).send())
		                    .wiretap()
		                    .bindNow();

		response = HttpClient.create(8080).get("/").block();

		// fails, response status is 200 and debugging shows the the previous handler is called
		assertThat(response.status().code()).isEqualTo(201);
		response.dispose();
		context.dispose();
		context.onDispose().block();
	}

	@Test
	public void errorResponseAndReturn() throws Exception {
		Connection c = HttpServer.create()
		                         .port(0)
		                         .handler((req, resp) -> Mono.error(new Exception("returnError")))
		                         .wiretap()
		                         .bindNow();

		HttpClientResponse res =
				HttpClient.create(c.address().getPort())
				          .get("/return")
				          .block();
		assertThat(res.status().code()).isEqualTo(500);
		res.dispose();

		c.dispose();

	}

	@Test
	public void httpPipelining() throws Exception {

		AtomicInteger i = new AtomicInteger();

		Connection server = HttpServer.create()
		                              .port(0)
		                              .handler((req, resp) -> resp.header(HttpHeaderNames.CONTENT_LENGTH, "1")
		                                                          .sendString(Mono.just(i.incrementAndGet())
		                                                                          .flatMap(d -> Mono.delay(
				                                                                          Duration.ofSeconds(
						                                                                          4 - d))
		                                                                                         .map(x -> d + "\n"))))
		                              .wiretap()
		                              .bindNow();

		DefaultFullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1,
				HttpMethod.GET,
				"/plaintext");

		CountDownLatch latch = new CountDownLatch(6);

		Connection client =TcpClient.create()
		                            .port(server.address().getPort())
		         .handler((in, out) -> {
			         in.withConnection(x -> x
			           .addHandlerFirst(new HttpClientCodec()))

			         .receiveObject()
			           .ofType(DefaultHttpContent.class)
			           .as(ByteBufFlux::fromInbound)
			           .asString()
			           .log()
			           .map(Integer::parseInt)
			           .subscribe(d -> {
				           for (int x = 0; x < d; x++) {
					           latch.countDown();
				           }
			           });

			                                   return out.sendObject(Flux.just(request.retain(),
					                                                           request.retain(),
					                                                           request.retain()))
			                                             .neverComplete();
		                               })
		                               .wiretap()
		                               .connectNow();

		Assert.assertTrue(latch.await(45, TimeUnit.SECONDS));

		server.dispose();
		client.dispose();
	}

	@Test
	public void flushOnComplete() {

		Flux<String> test = Flux.range(0, 100)
		                        .map(n -> String.format("%010d", n));

		Connection c = HttpServer.create()
		                         .port(0)
		                         .handler((req, resp) -> resp.sendString(test.map(s -> s + "\n")))
		                         .wiretap()
		                         .bindNow();

		Flux<String> client = HttpClient.create(c.address()
		                                         .getPort())
		                                .get("/")
		                                .block(Duration.ofSeconds(30))
		                                .addHandler(new LineBasedFrameDecoder(10))
		                                .receive()
		                                .asString();

		StepVerifier.create(client)
		            .expectNextSequence(test.toIterable())
		            .expectComplete()
		            .verify(Duration.ofSeconds(30));

		c.dispose();
	}

	@Test
	public void keepAlive() throws URISyntaxException {
		Path resource = Paths.get(getClass().getResource("/public").toURI());
		Connection c = HttpServer.create()
		                         .port(0)
		                         .router(routes -> routes.directory("/test", resource))
		                         .wiretap()
		                         .bindNow();

		HttpResources.set(PoolResources.fixed("http", 1));

		HttpClientResponse response0 = HttpClient.create(c.address()
		                                                  .getPort())
		                                         .get("/test/index.html")
		                                         .block(Duration.ofSeconds(30));

		HttpClientResponse response1 = HttpClient.create(c.address()
		                                                  .getPort())
		                                         .get("/test/test.css")
		                                         .block(Duration.ofSeconds(30));

		HttpClientResponse response2 = HttpClient.create(c.address()
		                                                  .getPort())
		                                         .get("/test/test1.css")
		                                         .block(Duration.ofSeconds(30));

		HttpClientResponse response3 = HttpClient.create(c.address()
		                                                  .getPort())
		                                         .get("/test/test2.css")
		                                         .block(Duration.ofSeconds(30));

		HttpClientResponse response4 = HttpClient.create(c.address()
		                                                  .getPort())
		                                         .get("/test/test3.css")
		                                         .block(Duration.ofSeconds(30));

		HttpClientResponse response5 = HttpClient.create(c.address()
		                                                  .getPort())
		                                         .get("/test/test4.css")
		                                         .block(Duration.ofSeconds(30));

		HttpClientResponse response6 = HttpClient.create(opts -> opts.port(c.address().getPort())
		                                                             .disablePool())
		                                         .get("/test/test5.css")
		                                         .block(Duration.ofSeconds(30));

		Assert.assertEquals(response0.channel(), response1.channel());
		Assert.assertEquals(response0.channel(), response2.channel());
		Assert.assertEquals(response0.channel(), response3.channel());
		Assert.assertEquals(response0.channel(), response4.channel());
		Assert.assertEquals(response0.channel(), response5.channel());
		Assert.assertNotEquals(response0.channel(), response6.channel());

		HttpResources.reset();
		response0.dispose();
		response1.dispose();
		response2.dispose();
		response3.dispose();
		response4.dispose();
		response5.dispose();
		response6.dispose();
		c.dispose();
	}

	@Test
	public void gettingOptionsDuplicates() {
		HttpServer server = HttpServer.create()
		                              .port(123)
		                              .tcpConfiguration(tcpServer -> tcpServer.host("foo"))
		                              .compress();
		assertThat(server.tcpConfiguration().configure())
		          .isNotSameAs(HttpServer.DEFAULT_TCP_SERVER)
		          .isNotSameAs(server.tcpConfiguration().configure());
	}

	@Test
	public void startRouter() {
		Connection facade = HttpServer.create()
		                              .port(0)
		                              .router(routes -> routes.get("/hello",
				                                        (req, resp) -> resp.sendString(Mono.just("hello!"))))
		                              .wiretap()
		                              .bindNow();

		try {
			HttpClientResponse res =
					HttpClient.create(facade.address().getPort())
					          .get("/hello")
					          .block();
			assertThat(res.status().code()).isEqualTo(200);
			res.dispose();

			res = HttpClient.create(facade.address().getPort())
			                .get("/helloMan")
			                .block();
			assertThat(res.status().code()).isEqualTo(404);
			res.dispose();
		}
		finally {
			facade.disposeNow();
		}
	}

	@Test
	public void startRouterAndAwait()
			throws InterruptedException {
		ExecutorService ex = Executors.newSingleThreadExecutor();
		AtomicReference<Connection> ref = new AtomicReference<>();

		Future<?> f = ex.submit(() ->
			    HttpServer.create()
			              .port(0)
			              .router(routes -> routes.get("/hello", (req, resp) -> resp.sendString(Mono.just("hello!"))))
			              .wiretap()
			              .bindUntilJavaShutdown(Duration.ofSeconds(2), c -> ref.set(c))
		);

		//if the server cannot be started, a ExecutionException will be thrown instead
		assertThatExceptionOfType(TimeoutException.class)
				.isThrownBy(() -> f.get(1, TimeUnit.SECONDS));

		//the router is not done and is still blocking the thread
		assertThat(f.isDone()).isFalse();
		assertThat(ref.get()).isNotNull().withFailMessage("Server is not initialized after 1s");

		//shutdown the router to unblock the thread
		ref.get().disposeNow();
		Thread.sleep(100);
		assertThat(f.isDone()).isTrue();
	}

	@Test
	public void nonContentStatusCodes() {
		Connection server =
				HttpServer.create()
				          .tcpConfiguration(tcpServer -> tcpServer.host("localhost"))
				          .router(r -> r.get("/204-1", (req, res) -> res.status(HttpResponseStatus.NO_CONTENT)
				                                                        .sendHeaders())
				                        .get("/204-2", (req, res) -> res.status(HttpResponseStatus.NO_CONTENT))
				                        .get("/205-1", (req, res) -> res.status(HttpResponseStatus.RESET_CONTENT)
				                                                        .sendHeaders())
				                        .get("/205-2", (req, res) -> res.status(HttpResponseStatus.RESET_CONTENT))
				                        .get("/304-1", (req, res) -> res.status(HttpResponseStatus.NOT_MODIFIED)
				                                                        .sendHeaders())
				                        .get("/304-2", (req, res) -> res.status(HttpResponseStatus.NOT_MODIFIED)))
				          .wiretap()
				          .bindNow();

		checkResponse("/204-1", server.address());
		checkResponse("/204-2", server.address());
		checkResponse("/205-1", server.address());
		checkResponse("/205-2", server.address());
		checkResponse("/304-1", server.address());
		checkResponse("/304-2", server.address());

		server.dispose();
	}

	private void checkResponse(String url, InetSocketAddress address) {
		Mono<HttpClientResponse> response =
				HttpClient.create(ops -> ops.connectAddress(() -> address))
				          .get(url);

		StepVerifier.create(response)
		            .expectNextMatches(r -> {
		                r.dispose();
		                int code = r.status().code();
		                HttpHeaders h = r.responseHeaders();
		                if (code == 204 || code == 304) {
		                    return !h.contains("Transfer-Encoding") &&
		                           !h.contains("Content-Length");
		                }
		                else if (code == 205) {
		                    return !h.contains("Transfer-Encoding") &&
		                            h.contains("Content-Length") &&
		                            Integer.parseInt(h.get("Content-Length")) == 0;
		                }
		                else {
		                    return false;
		                }
		            })
		            .expectComplete()
		            .verify(Duration.ofSeconds(30));
	}

	@Test
	public void testContentLengthHeadRequest() {
		Connection server =
				HttpServer.create()
				          .tcpConfiguration(tcpServer -> tcpServer.host("localhost"))
				          .router(r -> r.route(req -> req.uri().startsWith("/1"),
				                                  (req, res) -> res.sendString(Mono.just("OK")))
				                        .route(req -> req.uri().startsWith("/2"),
				                                  (req, res) -> res.chunkedTransfer(false)
				                                                   .sendString(Mono.just("OK")))
				                        .route(req -> req.uri().startsWith("/3"),
				                                  (req, res) -> {
				                                                res.responseHeaders().set("Content-Length", 2);
				                                                return res.sendString(Mono.just("OK"));
				                                                })
				                        .route(req -> req.uri().startsWith("/4"),
				                                  (req, res) -> res.sendHeaders())
				                        .route(req -> req.uri().startsWith("/5"),
				                                  (req, res) -> res.chunkedTransfer(false)
				                                                   .sendHeaders())
				                        .route(req -> req.uri().startsWith("/6"),
				                                  (req, res) -> {
				                                                res.responseHeaders().set("Content-Length", 2);
				                                                return res.sendHeaders();
				                                                })
				                        .route(req -> req.uri().startsWith("/7"),
				                                  (req, res) -> res.send())
				                        .route(req -> req.uri().startsWith("/8"),
				                                  (req, res) -> res.chunkedTransfer(false)
				                                                   .send())
				                        .route(req -> req.uri().startsWith("/9"),
				                                  (req, res) -> {
				                                                res.responseHeaders().set("Content-Length", 2);
				                                                return res.send();
				                                                })
				                        )
				          .wiretap()
				          .bindNow();

		doTestContentLengthHeadRequest("/1", server.address(), HttpMethod.GET, true, false);
		doTestContentLengthHeadRequest("/1", server.address(), HttpMethod.HEAD, true, false);
		doTestContentLengthHeadRequest("/2", server.address(), HttpMethod.GET, false, true);
		doTestContentLengthHeadRequest("/2", server.address(), HttpMethod.HEAD, false, true);
		doTestContentLengthHeadRequest("/3", server.address(), HttpMethod.GET, false, false);
		doTestContentLengthHeadRequest("/3", server.address(), HttpMethod.HEAD, false, false);
		doTestContentLengthHeadRequest("/4", server.address(), HttpMethod.HEAD, true, false);
		doTestContentLengthHeadRequest("/5", server.address(), HttpMethod.HEAD, false, true);
		doTestContentLengthHeadRequest("/6", server.address(), HttpMethod.HEAD, false, false);
		doTestContentLengthHeadRequest("/7", server.address(), HttpMethod.HEAD, true, false);
		doTestContentLengthHeadRequest("/8", server.address(), HttpMethod.HEAD, false, true);
		doTestContentLengthHeadRequest("/9", server.address(), HttpMethod.HEAD, false, false);

		server.dispose();
	}

	private void doTestContentLengthHeadRequest(String url, InetSocketAddress address,
			HttpMethod method, boolean chunk, boolean close) {
		Mono<Tuple2<HttpHeaders, String>> response =
				HttpClient.create(ops -> ops.connectAddress(() -> address))
				          .request(method, url, req -> req.send())
				          .flatMap(res -> Mono.zip(Mono.just(res.responseHeaders()),
				                                   res.receive()
				                                      .aggregate()
				                                      .asString()
				                                      .defaultIfEmpty("NO BODY")));

		StepVerifier.create(response)
				    .expectNextMatches(t -> {
				        if (chunk) {
				            String chunked = t.getT1().get("Transfer-Encoding");
				            if (HttpMethod.GET.equals(method)) {
				                return chunked != null && "OK".equals(t.getT2());
				            }
				            else {
				                return chunked == null && "NO BODY".equals(t.getT2());
				            }
				        }
				        else if (close) {
				            String connClosed = t.getT1().get("Connection");
				            if (HttpMethod.GET.equals(method)) {
				                return "close".equals(connClosed) && "OK".equals(t.getT2());
				            }
				            else {
				                return "close".equals(connClosed) && "NO BODY".equals(t.getT2());
				            }
				        }
				        else {
				            String length = t.getT1().get("Content-Length");
				            if (HttpMethod.GET.equals(method)) {
				                return Integer.parseInt(length) == 2 && "OK".equals(t.getT2());
				            }
				            else {
				                return Integer.parseInt(length) == 2 && "NO BODY".equals(t.getT2());
				            }
				        }
				    })
				    .expectComplete()
				    .verify();
	}

	@Test
	public void testIssue186() {
		DisposableChannel server =
				HttpServer.create()
				          .port(0)
				          .handler((req, res) -> res.status(200).send())
				          .wiretap()
				          .bindNow();

		HttpClient client =
				HttpClient.create(ops -> ops.connectAddress(() -> server.address())
						                    .poolResources(PoolResources.fixed("test", 1)));

		try {
			doTestIssue186(client);
			doTestIssue186(client);
		}
		finally {
			server.dispose();
		}

	}

	private void doTestIssue186(HttpClient client) {
		Mono<String> content = client.post("/", req -> req.sendString(Mono.just("bodysample")))
				                      .flatMap(res -> res.receive()
				                                         .aggregate()
				                                         .asString());

		StepVerifier.create(content)
		            .expectComplete()
		            .verify(Duration.ofSeconds(300));
	}*/
}
