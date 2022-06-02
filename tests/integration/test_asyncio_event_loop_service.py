from unittest.mock import MagicMock

import pytest

from linkurator_core.application.event_bus_service import Event, EventType
from linkurator_core.infrastructure.asyncio.event_bus_service import AsyncioEventBusService
from linkurator_core.infrastructure.asyncio.utils import run_parallel, run_sequence, wait_until


@pytest.mark.asyncio
async def test_publish_and_subscribe() -> None:
    event_bus = AsyncioEventBusService()
    dummy_function = MagicMock()
    event_bus.subscribe(EventType.ACCOUNT_CREATED, dummy_function)
    event_bus.publish(Event(EventType.ACCOUNT_CREATED, 'dummy_data'))

    results = await run_parallel(
        event_bus.start(),
        run_sequence(
            wait_until(lambda: dummy_function.call_count == 1),
            event_bus.stop()
        )
    )

    condition_was_met_in_time = results[1][0]
    assert condition_was_met_in_time
