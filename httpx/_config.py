import logging
import os
import ssl
import typing
import logging  # Add the import statement for the logging module
from pathlib import Path

import certifi

from ._compat import set_minimum_tls_version_1_2
from ._models import Headers
from ._types import CertTypes, HeaderTypes, TimeoutTypes, URLTypes, VerifyTypes
from ._urls import URL
from ._utils import get_ca_bundle_from_env

SOCKET_OPTION = typing.Union[
    typing.Tuple[int, int, int],
    typing.Tuple[int, int, typing.Union[bytes, bytearray]],
    typing.Tuple[int, int, None, int],
]

DEFAULT_CIPHERS = ":".join(
    [
        "ECDHE+AESGCM",
        "ECDHE+CHACHA20",
        "DHE+AESGCM",
        "DHE+CHACHA20",
        "ECDH+AESGCM",
        "DH+AESGCM",
        "ECDH+AES",
        "DH+AES",
        "RSA+AESGCM",
        "RSA+AES",
        "!aNULL",
        "!eNULL",
        "!MD5",
        "!DSS",
    ]
)

logger = logging.getLogger("httpx")

class UnsetType:
    pass  # pragma: no cover

UNSET = UnsetType()

# Rest of the code remains unchanged

        # Disable using 'commonName' for SSLContext.check_hostname
        # when the 'subjectAltName' extension isn't available.
        try:
            context.hostname_checks_common_name = False
        except AttributeError:  # pragma: no cover
            pass

        if ca_bundle_path.is_file():
            cafile = str(ca_bundle_path)
            logger.debug("load_verify_locations cafile=%r", cafile)
            context.load_verify_locations(cafile=cafile)
        elif ca_bundle_path.is_dir():
            capath = str(ca_bundle_path)
            logger.debug("load_verify_locations capath=%r", capath)
            context.load_verify_locations(capath=capath)

        self._load_client_certs(context)

        return context

    def _create_default_ssl_context(self) -> ssl.SSLContext:
        """
        Creates the default SSLContext object that's used for both verified
        and unverified connections.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        set_minimum_tls_version_1_2(context)
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_ciphers(DEFAULT_CIPHERS)

        if ssl.HAS_ALPN:
            alpn_idents = ["http/1.1", "h2"] if self.http2 else ["http/1.1"]
            context.set_alpn_protocols(alpn_idents)

        keylogfile = os.environ.get("SSLKEYLOGFILE")
        if keylogfile and self.trust_env:
            context.keylog_filename = keylogfile

        return context

    def _load_client_certs(self, ssl_context: ssl.SSLContext) -> None:
        """
        Loads client certificates into our SSLContext object
        """
        if self.cert is not None:
            if isinstance(self.cert, str):
                ssl_context.load_cert_chain(certfile=self.cert)
            elif isinstance(self.cert, tuple) and len(self.cert) == 2:
                ssl_context.load_cert_chain(certfile=self.cert[0], keyfile=self.cert[1])
            elif isinstance(self.cert, tuple) and len(self.cert) == 3:
                ssl_context.load_cert_chain(
                    certfile=self.cert[0],
                    keyfile=self.cert[1],
                    password=self.cert[2],
                )


class Timeout:
    """
    Timeout configuration.

    **Usage**:

    Timeout(None)               # No timeouts.
    Timeout(5.0)                # 5s timeout on all operations.
    Timeout(None, connect=5.0)  # 5s timeout on connect, no other timeouts.
    Timeout(5.0, connect=10.0)  # 10s timeout on connect. 5s timeout elsewhere.
    Timeout(5.0, pool=None)     # No timeout on acquiring connection from pool.
                                # 5s timeout elsewhere.
    """

    def __init__(
        self,
        timeout: typing.Union[TimeoutTypes, UnsetType] = UNSET,
        *,
        connect: typing.Union[None, float, UnsetType] = UNSET,
        read: typing.Union[None, float, UnsetType] = UNSET,
        write: typing.Union[None, float, UnsetType] = UNSET,
        pool: typing.Union[None, float, UnsetType] = UNSET,
    ) -> None:
        if isinstance(timeout, Timeout):
            # Passed as a single explicit Timeout.
            assert connect is UNSET
            assert read is UNSET
            assert write is UNSET
            assert pool is UNSET
            self.connect = timeout.connect  # type: typing.Optional[float]
            self.read = timeout.read  # type: typing.Optional[float]
            self.write = timeout.write  # type: typing.Optional[float]
            self.pool = timeout.pool  # type: typing.Optional[float]
        elif isinstance(timeout, tuple):
            # Passed as a tuple.
            self.connect = timeout[0]
            self.read = timeout[1]
            self.write = None if len(timeout) < 3 else timeout[2]
            self.pool = None if len(timeout) < 4 else timeout[3]
        elif not (
            isinstance(connect, UnsetType)
            or isinstance(read, UnsetType)
        if ca_bundle_path.is_file():
            cafile = str(ca_bundle_path)
            logger.debug("load_verify_locations cafile=%r", cafile)
            context.load_verify_locations(cafile=cafile)
        elif ca_bundle_path.is_dir():
            capath = str(ca_bundle_path)
            logger.debug("load_verify_locations capath=%r", capath)
            context.load_verify_locations(capath=capath)
        else:
            raise ValueError("Invalid CA bundle path: {}".format(ca_bundle_path))

        self._load_client_certs(context)

        return context
            self.connect = timeout if isinstance(connect, UnsetType) else connect
            self.read = timeout if isinstance(read, UnsetType) else read
            self.write = timeout if isinstance(write, UnsetType) else write
            self.pool = timeout if isinstance(pool, UnsetType) else pool

    def as_dict(self) -> typing.Dict[str, typing.Optional[float]]:
        return {
            "connect": self.connect,
            "read": self.read,
            "write": self.write,
            "pool": self.pool,
        }

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.connect == other.connect
            and self.read == other.read
            and self.write == other.write
            and self.pool == other.pool
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        if len({self.connect, self.read, self.write, self.pool}) == 1:
            return f"{class_name}(timeout={self.connect})"
        return (
            f"{class_name}(connect={self.connect}, "
            f"read={self.read}, write={self.write}, pool={self.pool})"
        )


class Limits:
    """
    Configuration for limits to various client behaviors.

    **Parameters:**

    * **max_connections** - The maximum number of concurrent connections that may be
            established.
    * **max_keepalive_connections** - Allow the connection pool to maintain
            keep-alive connections below this point. Should be less than or equal
            to `max_connections`.
    * **keepalive_expiry** - Time limit on idle keep-alive connections in seconds.
    """

    def __init__(
        self,
        *,
        max_connections: typing.Optional[int] = None,
        max_keepalive_connections: typing.Optional[int] = None,
        keepalive_expiry: typing.Optional[float] = 5.0,
    ) -> None:
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, self.__class__)
            and self.max_connections == other.max_connections
            and self.max_keepalive_connections == other.max_keepalive_connections
            and self.keepalive_expiry == other.keepalive_expiry
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return (
            f"{class_name}(max_connections={self.max_connections}, "
            f"max_keepalive_connections={self.max_keepalive_connections}, "
            f"keepalive_expiry={self.keepalive_expiry})"
        )


class Proxy:
    def __init__(
        self,
        url: URLTypes,
        *,
        ssl_context: typing.Optional[ssl.SSLContext] = None,
        auth: typing.Optional[typing.Tuple[str, str]] = None,
        headers: typing.Optional[HeaderTypes] = None,
    ) -> None:
        url = URL(url)
        headers = Headers(headers)

        if url.scheme not in ("http", "https", "socks5"):
            raise ValueError(f"Unknown scheme for proxy URL {url!r}")

        if url.username or url.password:
            # Remove any auth credentials from the URL.
            auth = (url.username, url.password)
            url = url.copy_with(username=None, password=None)

        self.url = url
        self.auth = auth
        self.headers = headers
        self.ssl_context = ssl_context

    @property
    def raw_auth(self) -> typing.Optional[typing.Tuple[bytes, bytes]]:
        # The proxy authentication as raw bytes.
        return (
            None
            if self.auth is None
            else (self.auth[0].encode("utf-8"), self.auth[1].encode("utf-8"))
        )

    def __repr__(self) -> str:
        # The authentication is represented with the password component masked.
        auth = (self.auth[0], "********") if self.auth else None

        # Build a nice concise representation.
        url_str = f"{str(self.url)!r}"
        auth_str = f", auth={auth!r}" if auth else ""
        headers_str = f", headers={dict(self.headers)!r}" if self.headers else ""
        return f"Proxy({url_str}{auth_str}{headers_str})"


class NetworkOptions:
    def __init__(
        self,
        connection_retries: int = 0,
        local_address: typing.Optional[str] = None,
        socket_options: typing.Optional[typing.Iterable[SOCKET_OPTION]] = None,
        uds: typing.Optional[str] = None,
    ) -> None:
        self.connection_retries = connection_retries
        self.local_address = local_address
        self.socket_options = socket_options
        self.uds = uds

    def __repr__(self) -> str:
        defaults = {
            "connection_retries": 0,
            "local_address": None,
            "socket_options": None,
            "uds": None,
        }
        params = ", ".join(
            [
                f"{attr}={getattr(self, attr)!r}"
                for attr, default in defaults.items()
                if getattr(self, attr) != default
            ]
        )
        return f"NetworkOptions({params})"


DEFAULT_TIMEOUT_CONFIG = Timeout(timeout=5.0)
DEFAULT_LIMITS = Limits(max_connections=100, max_keepalive_connections=20)
DEFAULT_NETWORK_OPTIONS = NetworkOptions(connection_retries=0)
DEFAULT_MAX_REDIRECTS = 20
