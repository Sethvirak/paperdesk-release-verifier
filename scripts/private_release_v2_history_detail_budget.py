"""Pure, fixed detail-read policy owned by one bootstrap canary lifecycle."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


MAX_TERMINAL_POLLS = 180
MAX_DETAIL_READS = 4 * (1 + MAX_TERMINAL_POLLS + 1)


def _entries_digest(entries: Any) -> str:
    return hashlib.sha256((json.dumps(
        entries, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode("utf-8")).hexdigest()


class CanaryWebJobHistoryDetailBudget:
    """No caller-selected capacity, reset, refund, or provider operation."""

    def __init__(
        self, *, site_resource_id: str, job_name: str,
        error_type: type[RuntimeError],
    ) -> None:
        self._target = (site_resource_id, job_name)
        # The bootstrap supplies its normal failure type once. This does not
        # choose a limit or change any successful state transition.
        self._error_type = error_type
        self._remaining = MAX_DETAIL_READS
        self._phase = "history-boundary"
        self._boundary_sha256: str | None = None
        self._final_reserve = 0
        self._pending = 0
        self._active = False

    def _fail(self, message: str) -> None:
        raise self._error_type(message)

    def require_stage(
        self, *, site_resource_id: str, job_name: str, stage: str | None,
    ) -> None:
        if (
            (site_resource_id, job_name) != self._target or self._active
            or not (
                stage == self._phase
                or (stage == "final-history-census" and self._phase == "terminal-history")
            )
            or self._phase == "final-history-census"
        ):
            self._fail("WebJob history detail budget lifecycle or target is not exact")

    def admit_census(
        self, *, site_resource_id: str, job_name: str,
        stage: str | None, detail_count: int,
    ) -> None:
        self.require_stage(
            site_resource_id=site_resource_id, job_name=job_name, stage=stage,
        )
        if type(detail_count) is not int or not 0 <= detail_count <= 1000:
            self._fail("WebJob history detail budget census is not exact")
        if stage == "history-boundary":
            available = self._remaining
        elif stage == "terminal-history":
            available = self._remaining - self._final_reserve
        else:
            available = min(self._remaining, self._final_reserve)
        if detail_count > available:
            self._fail("WebJob history census exceeds its shared detail read budget")
        if stage == "final-history-census":
            self._phase = stage
        self._pending = detail_count
        self._active = True

    def charge_detail(self) -> None:
        # Charge before the single-attempt transport. An envelope rejection,
        # timeout, malformed response or later census never refunds the credit.
        if not self._active or self._pending <= 0 or self._remaining <= 0:
            self._fail("WebJob history detail read lacks an admitted budget credit")
        self._pending -= 1
        self._remaining -= 1

    def finish_census(self) -> None:
        if not self._active or self._pending != 0:
            self._fail("WebJob history detail census did not consume its exact credits")
        self._active = False

    def seal_boundary(self, boundary: Mapping[str, Any]) -> None:
        entries = boundary.get("entries")
        if (
            self._phase != "history-boundary" or self._active
            or self._boundary_sha256 is not None or not isinstance(entries, list)
            or any(not isinstance(item, Mapping) for item in entries)
        ):
            self._fail("WebJob history detail budget boundary is not exact")
        # Any old run may become sparse later. Reserve from the complete
        # projected universe plus one new run, never the current sparse count.
        reserve = len(entries) + 1
        if self._remaining < 2 * reserve:
            self._fail("WebJob history detail budget lacks pre-trigger census headroom")
        self._boundary_sha256 = _entries_digest(entries)
        self._final_reserve = reserve
        self._phase = "terminal-history"

    def require_boundary(self, boundary: Mapping[str, Any]) -> None:
        if (
            self._phase != "terminal-history" or self._boundary_sha256 is None
            or _entries_digest(boundary.get("entries")) != self._boundary_sha256
        ):
            self._fail("WebJob history detail budget differs from its sealed boundary")
