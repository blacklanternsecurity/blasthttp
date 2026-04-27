import sys

from . import _native
from ._native import (
    BatchConfig,
    BatchResult,
    BatchResultIterator,
    CertInfo,
    RawConnection,
    RedirectHop,
    Response,
    ResponseHash,
    __version__,
)
from ._native import h2

sys.modules["blasthttp.h2"] = h2


class BlastHTTP:
    """Async HTTP client backed by the Rust engine.

    Thin wrapper over the native ``_native.BlastHTTP`` pyclass. All methods
    and getters are forwarded through ``__getattr__``; the one exception is
    ``request_batch_stream``, which re-shapes the native iterator's batched
    output (``list[BatchResult]`` per ``__anext__``) into a per-item async
    generator so callers can write::

        async for r in client.request_batch_stream(configs):
            ...
    """

    def __init__(self):
        self._inner = _native.BlastHTTP()

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def request_batch_stream(self, configs, concurrency=50, rate_limit=None):
        it = self._inner.request_batch_stream(configs, concurrency, rate_limit)
        async for batch in it:
            for r in batch:
                yield r


__all__ = [
    "BlastHTTP",
    "BatchConfig",
    "BatchResult",
    "BatchResultIterator",
    "CertInfo",
    "RawConnection",
    "RedirectHop",
    "Response",
    "ResponseHash",
    "__version__",
]
