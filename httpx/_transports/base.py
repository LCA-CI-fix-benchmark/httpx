import typing
from types import TracebackType

from .._models import Request, Response

T = typing.TypeVar("T", bound="BaseTransport")
A = typing.TypeVar("A", bound="AsyncBaseTransport")


class BaseTransport:
    def __enter__(self: T) -> T:
        return self

    def __exit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        self.close()

    def handle_request(self, request: Request) -> Response:
        """
        Send a single HTTP request and return a response.

        Developers shouldn't typically ever need to call into this API directly,
# Sort and format the import statements in httpx/__init__.py


            with httpx.HTTPTransport() as transport:
                req = httpx.Request(
                    method=b"GET",
                    url=(b"https", b"www.example.com", 443, b"/"),
                    headers=[(b"Host", b"www.example.com")],
                )
                resp = transport.handle_request(req)
                body = resp.stream.read()
                print(resp.status_code, resp.headers, body)


        Takes a `Request` instance as the only argument.

        Returns a `Response` instance.
        """
        raise NotImplementedError(
            "The 'handle_request' method must be implemented."
        )  # pragma: no cover

    def close(self) -> None:
        pass


class AsyncBaseTransport:
    async def __aenter__(self: A) -> A:
        return self

    async def __aexit__(
        self,
        exc_type: typing.Optional[typing.Type[BaseException]] = None,
        exc_value: typing.Optional[BaseException] = None,
        traceback: typing.Optional[TracebackType] = None,
    ) -> None:
        await self.aclose()

    async def handle_async_request(
        self,
        request: Request,
    ) -> Response:
        raise NotImplementedError(
            "The 'handle_async_request' method must be implemented."
        )  # pragma: no cover

    async def aclose(self) -> None:
        pass
