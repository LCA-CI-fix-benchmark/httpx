"""
Custom transports, with nicely configured defaults.

The following additional keyword arguments are currently supported by httpcore...

* uds: str
* local_address: str
* retries: int

Example usages...

# Disable HTTP/2 on a single specific domain.
mounts = {
    "all://": httpx.HTTPTransport(http2=True),
    "all://*example.org": httpx.HTTPTransport()
}

# Using advanced httpcore configuration, with connection retries.
transport = httpx.HTTPTransport(retries=1)
client = httpx.Client(transport=transport)

# Using advanced httpcore configuration, with unix domain sockets.
transport = httpx.HTTPTransport(uds="socket.uds")
client = httpx.Client(transport=transport)
"""
import contextlib
import typing
from types import TracebackType

import httpcore

from .._config import (
    DEFAULT_LIMITS,
    DEFAULT_NETWORK_OPTIONS,
    Proxy,
    Limits,
    NetworkOptions,
    create_ssl_context,
)
from .._exceptions import (
    ConnectTimeout,
    ConnectError,
    ConnectTimeout,
    ConnectError,
    ConnectTimeout,
    ConnectError,
)
from .._models import (
    Request,
    Response,
)
from .._version import __version__, version_info


class DefaultTransport(HTTPTransport):
    """Default HTTP transport implementation."""

    def __init__(
        self,
        verify: VerifyTypes = True,
        cert: CertTypes = None,
        limits: Limits = DEFAULT_LIMITS,
        network_options: NetworkOptions = DEFAULT_NETWORK_OPTIONS,
        proxy: typing.Union[str, Proxy] = None,
        event_handler: typing.Callable = None,
    ) -> None:
        super().__init__(
            verify=verify,
            cert=cert,
            limits=limits,
            network_options=network_options,
            proxy=proxy,
            event_handler=event_handler,
        )
        self._is_verifying = verify
        self._ssl_context = create_ssl_context(verify=verify, cert=cert)

    def __enter__(self) -> "DefaultTransport":
        return self

    def __exit__(self, *args: typing.Any) -> None:
        self.close()

    @property
    def is_verifying(self) -> bool:
        return self._is_verifying

    @property
    def ssl_context(self) -> "ssl.SSLContext":
        return self._ssl_context

    def handle_async_request(
        self, request: Request, timeout: typing.Optional[float] = None
    ) -> asyncio.Future:
        loop = asyncio.get_event_loop()
        return asyncio.ensure_future(self.handle_request(request, timeout=timeout))

    async def handle_request(
        self, request: Request, timeout: typing.Optional[float] = None
    ) -> Response:
        try:
            async with self._create_connection(request) as connection:
                return await self._send_request(connection, request, timeout)
        except OSError as exc:
            raise ConnectError(str(exc)) from exc

    async def _create_connection(
        self, request: Request, timeout: typing.Optional[float] = None
    ) -> HTTPConnection:
        timeout, deadline = self._resolve_timeout(timeout)
        scheme = request.url.scheme
        host = request.url.host
        port = request.url.port

        sock_options = self._get_socket_options(request)
        ssl = scheme == "https" and self.is_verifying
        ssl_context = self.ssl_context if ssl else None

        if ssl:
            proxy = None
        else:
            proxy = self._get_proxy(request)

        connection_factory = self._get_connection_factory(request)
        connection = await connection_factory(
            scheme, host, port, timeout=timeout, ssl=ssl, ssl_context=ssl_context, proxies=proxy, sock_options=sock_options, deadline=deadline
        )

        return connection

    def _get_socket_options(self, request: Request) -> typing.Optional[typing.Iterable[typing.Union[int, str]]]:
        socket_options = None
        timeout = self._get_timeout(request)
        if timeout is not None:
            socket_options = self._get_socket_options_from_timeout(timeout)
        return socket_options

    @staticmethod
    def _get_socket_options_from_timeout(timeout: float) -> typing.Optional[typing.Iterable[typing.Union[int, str]]]:
        socket_options = [(socket.SOL_SOCKET, socket.SO_SNDTIMEO, int(timeout * 1000)), (socket.SOL_SOCKET, socket.SO_RCVTIMEO, int(timeout * 1000))]
        return socket_options

    def _get_proxy(self, request: Request) -> typing.Optional[typing.Union[str, Proxy]]:
        proxy = None
        if self.proxy:
            proxy = self.proxy
        elif request.proxy:
            proxy = request.proxy
        return proxy

    def _get_connection_factory(self, request: Request) -> typing.Callable:
        connection_factory = self._get_connection_factory_using_pool
        if request.url.scheme == "https" or self.is_verifying:
            connection_factory = self._get_connection_factory_using_pool
        else:
            connection_factory = self._create_connection
        return connection_factory

    def _get_connection_factory_using_pool(
        self, scheme: str, host: str, port: int, timeout: float, ssl: bool, ssl_context: typing.Optional["ssl.SSLContext"], proxies: typing.Optional[typing.Union[str, Proxy]], sock_options: typing.Optional[typing.Iterable[typing.Union[int, str]]], deadline: typing.Optional[float]
    ) -> typing.Callable:
        return self._connection_pool.connection

    def _create_connection(
        self, scheme: str, host: str, port: int, timeout: float, ssl: bool, ssl_context: typing.Optional["ssl.SSLContext"], proxies: typing.Optional[typing.Union[str, Proxy]], sock_options: typing.Optional[typing.Iterable[typing.Union[int, str]]], deadline: typing.Optional[float]
    ) -> HTTPConnection:
        connection_class = HTTPConnection
        if ssl:
            connection_class = VerifiedHTTPSConnection
        connection = connection_class(
            host=host,
            port=port,
            timeout=timeout,
            ssl_context=ssl_context,
            proxies=proxies,
            sock_options=sock_options,
        )
        return connection

    def _resolve_timeout(self, timeout: typing.Optional[float]) -> typing.Tuple[typing.Optional[float], typing.Optional[float]]:
        if timeout is None:
            timeout = self.timeout
        deadline = None
        if timeout is not None:
            deadline = time.monotonic() + timeout
        return timeout, deadline

    def _get_timeout(self, request: Request) -> typing.Optional[float]:
        timeout = None
        if request.timeout is not None:
            timeout = request.timeout
        elif self.timeout is not None:
            timeout = self.timeout
        return timeout

    ConnectError,
    ConnectTimeout,
    LocalProtocolError,
    NetworkError,
    PoolTimeout,
    ProtocolError,
    ProxyError,
    ReadError,
    ReadTimeout,
    RemoteProtocolError,
    TimeoutException,
    UnsupportedProtocol,
    WriteError,
    WriteTimeout,
)
from .._models import Request, Response
from .._types import AsyncByteStream, CertTypes, ProxyTypes, SyncByteStream, VerifyTypes
from .._urls import URL
from .base import AsyncBaseTransport, BaseTransport

T = typing.TypeVar("T", bound="HTTPTransport")
A = typing.TypeVar("A", bound="AsyncHTTPTransport")


@contextlib.contextmanager
def map_httpcore_exceptions() -> typing.Iterator[None]:
    try:
        yield
    except Exception as exc:
        mapped_exc = None

        for from_exc, to_exc in HTTPCORE_EXC_MAP.items():
            if not isinstance(exc, from_exc):
                continue
            # We want to map to the most specific exception we can find.
            # Eg if `exc` is an `httpcore.ReadTimeout`, we want to map to
            # `httpx.ReadTimeout`, not just `httpx.TimeoutException`.
            if mapped_exc is None or issubclass(to_exc, mapped_exc):
                mapped_exc = to_exc

        if mapped_exc is None:  # pragma: no cover
            raise

        message = str(exc)
        raise mapped_exc(message) from exc


HTTPCORE_EXC_MAP = {
    httpcore.TimeoutException: TimeoutException,
    httpcore.ConnectTimeout: ConnectTimeout,
    httpcore.ReadTimeout: ReadTimeout,
    httpcore.WriteTimeout: WriteTimeout,
    httpcore.PoolTimeout: PoolTimeout,
    httpcore.NetworkError: NetworkError,
    httpcore.ConnectError: ConnectError,
    httpcore.ReadError: ReadError,
    httpcore.WriteError: WriteError,
    httpcore.ProxyError: ProxyError,
    httpcore.UnsupportedProtocol: UnsupportedProtocol,
    httpcore.ProtocolError: ProtocolError,
    httpcore.LocalProtocolError: LocalProtocolError,
    httpcore.RemoteProtocolError: RemoteProtocolError,
}


class ResponseStream(SyncByteStream):
    def __init__(self, httpcore_stream: typing.Iterable[bytes]) -> None:
        self._httpcore_stream = httpcore_stream

    def __iter__(self) -> typing.Iterator[bytes]:
        with map_httpcore_exceptions():
            for part in self._httpcore_stream:
                yield part

    def close(self) -> None:
        if hasattr(self._httpcore_stream, "close"):
            self._httpcore_stream.close()


class HTTPTransport(BaseTransport):
    def __init__(
        self,
        verify: VerifyTypes = True,
        cert: typing.Optional[CertTypes] = None,
        http1: bool = True,
        http2: bool = False,
        limits: Limits = DEFAULT_LIMITS,
        trust_env: bool = True,
        proxy: typing.Optional[ProxyTypes] = None,
        network_options: NetworkOptions = DEFAULT_NETWORK_OPTIONS,
    ) -> None:
        ssl_context = create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        proxy = Proxy(url=proxy) if isinstance(proxy, (str, URL)) else proxy

        if proxy is None:
            self._pool = httpcore.ConnectionPool(
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
                uds=network_options.uds,
                local_address=network_options.local_address,
                retries=network_options.connection_retries,
                socket_options=network_options.socket_options,
            )
        elif proxy.url.scheme in ("http", "https"):
            self._pool = httpcore.HTTPProxy(
                proxy_url=httpcore.URL(
                    scheme=proxy.url.raw_scheme,
                    host=proxy.url.raw_host,
                    port=proxy.url.port,
                    target=proxy.url.raw_path,
                ),
                proxy_auth=proxy.raw_auth,
                proxy_headers=proxy.headers.raw,
                ssl_context=ssl_context,
                proxy_ssl_context=proxy.ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
                uds=network_options.uds,
                local_address=network_options.local_address,
                retries=network_options.connection_retries,
                socket_options=network_options.socket_options,
            )
        elif proxy.url.scheme == "socks5":
            try:
                import socksio  # noqa
            except ImportError:  # pragma: no cover
                raise ImportError(
                    "Using SOCKS proxy, but the 'socksio' package is not installed. "
                    "Make sure to install httpx using `pip install httpx[socks]`."
                ) from None

            self._pool = httpcore.SOCKSProxy(
                proxy_url=httpcore.URL(
                    scheme=proxy.url.raw_scheme,
                    host=proxy.url.raw_host,
                    port=proxy.url.port,
                    target=proxy.url.raw_path,
                ),
                proxy_auth=proxy.raw_auth,
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
            )
        else:  # pragma: no cover
            raise ValueError(
                "Proxy protocol must be either 'http', 'https', or 'socks5',"
                f" but got {proxy.url.scheme!r}."
            )

    def __enter__(self: T) -> T:  # Use generics for subclass support.
        self._pool.__enter__()
        return self

    def __exit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        with map_httpcore_exceptions():
            self._pool.__exit__(exc_type, exc_value, traceback)

    def handle_request(
        self,
        request: Request,
    ) -> Response:
        assert isinstance(request.stream, SyncByteStream)

        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            resp = self._pool.handle_request(req)

        assert isinstance(resp.stream, typing.Iterable)

        return Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=ResponseStream(resp.stream),
            extensions=resp.extensions,
        )

    def close(self) -> None:
        self._pool.close()


class AsyncResponseStream(AsyncByteStream):
    def __init__(self, httpcore_stream: typing.AsyncIterable[bytes]) -> None:
        self._httpcore_stream = httpcore_stream

    async def __aiter__(self) -> typing.AsyncIterator[bytes]:
        with map_httpcore_exceptions():
            async for part in self._httpcore_stream:
                yield part

    async def aclose(self) -> None:
        if hasattr(self._httpcore_stream, "aclose"):
            await self._httpcore_stream.aclose()


class AsyncHTTPTransport(AsyncBaseTransport):
    def __init__(
        self,
        verify: VerifyTypes = True,
        cert: typing.Optional[CertTypes] = None,
        http1: bool = True,
        http2: bool = False,
        limits: Limits = DEFAULT_LIMITS,
        trust_env: bool = True,
        proxy: typing.Optional[ProxyTypes] = None,
        network_options: NetworkOptions = DEFAULT_NETWORK_OPTIONS,
    ) -> None:
        ssl_context = create_ssl_context(verify=verify, cert=cert, trust_env=trust_env)
        proxy = Proxy(url=proxy) if isinstance(proxy, (str, URL)) else proxy

        if proxy is None:
            self._pool = httpcore.AsyncConnectionPool(
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
                uds=network_options.uds,
                local_address=network_options.local_address,
                retries=network_options.connection_retries,
                socket_options=network_options.socket_options,
            )
        elif proxy.url.scheme in ("http", "https"):
            self._pool = httpcore.AsyncHTTPProxy(
                proxy_url=httpcore.URL(
                    scheme=proxy.url.raw_scheme,
                    host=proxy.url.raw_host,
                    port=proxy.url.port,
                    target=proxy.url.raw_path,
                ),
                proxy_auth=proxy.raw_auth,
                proxy_headers=proxy.headers.raw,
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
                uds=network_options.uds,
                local_address=network_options.local_address,
                retries=network_options.connection_retries,
                socket_options=network_options.socket_options,
            )
        elif proxy.url.scheme == "socks5":
            try:
                import socksio  # noqa
            except ImportError:  # pragma: no cover
                raise ImportError(
                    "Using SOCKS proxy, but the 'socksio' package is not installed. "
                    "Make sure to install httpx using `pip install httpx[socks]`."
                ) from None

            self._pool = httpcore.AsyncSOCKSProxy(
                proxy_url=httpcore.URL(
                    scheme=proxy.url.raw_scheme,
                    host=proxy.url.raw_host,
                    port=proxy.url.port,
                    target=proxy.url.raw_path,
                ),
                proxy_auth=proxy.raw_auth,
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=http1,
                http2=http2,
            )
        else:  # pragma: no cover
            raise ValueError(
                "Proxy protocol must be either 'http', 'https', or 'socks5',"
                " but got {proxy.url.scheme!r}."
            )

    async def __aenter__(self: A) -> A:  # Use generics for subclass support.
        await self._pool.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        with map_httpcore_exceptions():
            await self._pool.__aexit__(exc_type, exc_value, traceback)

    async def handle_async_request(
        self,
        request: Request,
    ) -> Response:
        assert isinstance(request.stream, AsyncByteStream)

        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            resp = await self._pool.handle_async_request(req)

        assert isinstance(resp.stream, typing.AsyncIterable)

        return Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=AsyncResponseStream(resp.stream),
            extensions=resp.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
