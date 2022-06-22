from datetime import datetime
import http
from typing import Any, Callable, Optional
from uuid import UUID

from fastapi import Depends
from fastapi.applications import Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from pydantic.types import NonNegativeInt, PositiveInt

from linkurator_core.application.get_subscription_items_handler import GetSubscriptionItemsHandler
from linkurator_core.application.get_user_subscriptions_handler import GetUserSubscriptionsHandler
from linkurator_core.domain.session import Session
from linkurator_core.infrastructure.fastapi.models.item import ItemSchema
from linkurator_core.infrastructure.fastapi.models.page import Page
from linkurator_core.infrastructure.fastapi.models.subscription import SubscriptionSchema


def get_router(
        get_session: Callable,
        get_user_subscriptions_handler: GetUserSubscriptionsHandler,
        get_subscription_items_handler: GetSubscriptionItemsHandler
) -> APIRouter:
    router = APIRouter()

    @router.get("/", response_model=Page[SubscriptionSchema])
    async def get_all_subscriptions(
            request: Request,
            page_number: NonNegativeInt = 0,
            page_size: PositiveInt = 50,
            created_before_ts: float = datetime.now().timestamp(),
            session: Optional[Session] = Depends(get_session)
    ) -> Any:
        """
        Get the list of the user subscriptions
        """
        if session is None:
            return JSONResponse(status_code=http.HTTPStatus.UNAUTHORIZED)

        subscriptions, total_subs = get_user_subscriptions_handler.handle(
            session.user_id, page_number, page_size, datetime.fromtimestamp(created_before_ts))

        current_url = request.url.include_query_params(
            page_number=page_number,
            page_size=page_size,
            created_before_ts=created_before_ts
        )

        return Page[SubscriptionSchema].create(
            elements=[SubscriptionSchema.from_domain_subscription(subscription) for subscription in subscriptions],
            total_elements=total_subs,
            page_number=page_number,
            page_size=page_size,
            current_url=current_url)

    @router.get("/{sub_id}/items", response_model=Page[ItemSchema])
    async def get_subscription_items(
            request: Request,
            sub_id: UUID,
            page_number: NonNegativeInt = 0,
            page_size: PositiveInt = 5,
            created_before_ts: float = datetime.now().timestamp(),
            session: Optional[Session] = Depends(get_session)
    ) -> Any:
        """
        Get the list of subscription items sorted by published date. Newer items the first ones.
        :param request: HTTP request
        :param sub_id: UUID of the subscripton included in the url
        :param page_number: Number of the page to retrieve starting at 0 (query parameters)
        :param page_size: Number of elements per page (query paramenter)
        :param created_before_ts: Filter elements created before the timestamp (query paramenter)
        :param session: The session of the logged user
        :return: A page with the items. UNAUTHORIZED status code if the session is invalid.
        """

        if session is None:
            return JSONResponse(status_code=http.HTTPStatus.UNAUTHORIZED)

        items, total_items = get_subscription_items_handler.handle(
            subscription_id=sub_id,
            created_before=datetime.fromtimestamp(created_before_ts),
            page_number=page_number,
            page_size=page_size)

        current_url = request.url.include_query_params(
            page_number=page_number,
            page_size=page_size,
            created_before_ts=created_before_ts
        )

        return Page[ItemSchema].create(
            elements=[ItemSchema.from_domain_item(item) for item in items],
            total_elements=total_items,
            page_number=page_number,
            page_size=page_size,
            current_url=current_url)

    return router
