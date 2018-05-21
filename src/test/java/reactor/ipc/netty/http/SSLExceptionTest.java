package reactor.ipc.netty.http;

import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.ApplicationProtocolNegotiator;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSessionContext;
import org.junit.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.ipc.netty.NettyContext;
import reactor.ipc.netty.http.client.HttpClient;
import reactor.ipc.netty.http.client.HttpClientOptions;
import reactor.ipc.netty.http.server.HttpServer;
import reactor.test.StepVerifier;

public class SSLExceptionTest {
  @Test
  public void shouldNotThrowIllegalStateExceptionAfterSslException()
      throws CertificateException, SSLException, InterruptedException {
    CustomSslContext sslServer = new CustomSslContext();

    SslContext sslClient = SslContextBuilder.forClient()
        .trustManager(InsecureTrustManagerFactory.INSTANCE).build();

    NettyContext context =
        HttpServer.create(opt -> {
          opt.sslContext(sslServer).afterChannelInit(channel -> {

            channel.pipeline().addFirst(new ChannelInboundHandlerAdapter() {

              @Override
              public void channelRegistered(ChannelHandlerContext ctx) throws Exception {
                super.channelRegistered(ctx);

                ctx.channel().eventLoop().schedule(() -> {
                  sendSslCloseNotify(ctx);
                }, 5, TimeUnit.SECONDS);
              }

              private void sendSslCloseNotify(ChannelHandlerContext ctx) {
                try {
                  final SslHandler sslHandler = ctx.pipeline().get(SslHandler.class);
                  if (sslHandler != null) {
                    sslServer.getSslEngine(0).closeOutbound();

                    sslHandler.flush(ctx);
                  }
                } catch (Exception e) {
                  e.printStackTrace();
                }
              }

            });
          });
        }).newHandler((req, resp) -> resp.keepAlive(true).sendString(req.receive().asString().flatMap(x -> Flux
                .just("hello ", req.uri()))))
        .block();

    final HttpClient httpClient = HttpClient.create(
        opt -> applyHostAndPortFromContext(opt, context)
            .sslContext(sslClient));

    CountDownLatch errorLatch = new CountDownLatch(1);
    Flux.fromStream(IntStream.range(0, 5).boxed())
        .delayElements(Duration.ofMillis(2000))
        .flatMap(integer -> {
          return httpClient
              .get("/foo", httpClientRequest -> httpClientRequest.sendString(Flux.fromStream(IntStream.range(0, 100).mapToObj(Integer::toString))))
              .onErrorResume(throwable -> {
                System.out.println(throwable);
                errorLatch.countDown();
                return Mono.empty();
              });
        }, 1).subscribeOn(Schedulers.elastic())
        .subscribe(httpClientResponse -> {}, System.out::println);

    // Wait for javax.net.ssl.SSLException to have been thrown
    errorLatch.await();

    // javax.net.ssl.SSLException has been thrown, execute another request
    StepVerifier.create(httpClient
        .get("/foo", httpClientRequest -> httpClientRequest.sendString(Flux.fromStream(IntStream.range(0, 100).mapToObj(Integer::toString))))
    ).verifyComplete();
  }

  private HttpClientOptions.Builder applyHostAndPortFromContext(HttpClientOptions.Builder httpClientOptions, NettyContext context) {
    httpClientOptions.connectAddress(context::address);
    return httpClientOptions;
  }

  /**
   * SslContext that exposes created ssl engines.
   */
  private static class CustomSslContext extends SslContext {

    private final CopyOnWriteArrayList<SSLEngine> serverEngines;
    private SslContext delegate;

    public CustomSslContext() throws SSLException, CertificateException {
      SelfSignedCertificate ssc = new SelfSignedCertificate();
      this.serverEngines = new CopyOnWriteArrayList<>();
      delegate = SslContextBuilder.forServer(ssc.certificate(), ssc.privateKey()).build();
    }

    public SSLEngine getSslEngine(int index) {
      return serverEngines.get(index);
    }

    @Override
    public boolean isClient() {
      return delegate.isClient();
    }

    @Override
    public List<String> cipherSuites() {
      return delegate.cipherSuites();
    }

    @Override
    public long sessionCacheSize() {
      return delegate.sessionCacheSize();
    }

    @Override
    public long sessionTimeout() {
      return delegate.sessionTimeout();
    }

    @Override
    public ApplicationProtocolNegotiator applicationProtocolNegotiator() {
      return delegate.applicationProtocolNegotiator();
    }

    @Override
    public SSLEngine newEngine(ByteBufAllocator alloc) {
      final SSLEngine sslEngine = delegate.newEngine(alloc);

      serverEngines.add(sslEngine);
      return sslEngine;
    }

    @Override
    public SSLEngine newEngine(ByteBufAllocator alloc, String peerHost, int peerPort) {
      final SSLEngine sslEngine = delegate.newEngine(alloc, peerHost, peerPort);
      serverEngines.add(sslEngine);
      return sslEngine;
    }

    @Override
    public SSLSessionContext sessionContext() {
      return delegate.sessionContext();
    }
  }
}
