from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from bson.binary import UuidRepresentation
from bson.codec_options import CodecOptions
from pydantic import AnyUrl
from pydantic.main import BaseModel
import pymongo  # type: ignore
from pymongo import MongoClient
from pymongo.cursor import Cursor

from linkurator_core.domain.item import Item
from linkurator_core.domain.item_repository import ItemRepository
from linkurator_core.infrastructure.mongodb.repositories import CollectionIsNotInitialized


class MongoDBItem(BaseModel):
    uuid: UUID
    subscription_uuid: UUID
    name: str
    description: str
    url: AnyUrl
    thumbnail: AnyUrl
    created_at: datetime
    updated_at: datetime
    published_at: datetime

    @staticmethod
    def from_domain_item(item: Item) -> MongoDBItem:
        return MongoDBItem(
            uuid=item.uuid,
            subscription_uuid=item.subscription_uuid,
            name=item.name,
            description=item.description,
            url=item.url,
            thumbnail=item.thumbnail,
            created_at=item.created_at,
            updated_at=item.updated_at,
            published_at=item.published_at
        )

    def to_domain_item(self) -> Item:
        return Item(
            uuid=self.uuid,
            subscription_uuid=self.subscription_uuid,
            name=self.name,
            description=self.description,
            url=self.url,
            thumbnail=self.thumbnail,
            created_at=self.created_at,
            updated_at=self.updated_at,
            published_at=self.published_at
        )


class MongoDBItemRepository(ItemRepository):
    client: MongoClient
    db_name: str
    _collection_name: str = 'items'

    def __init__(self, ip: IPv4Address, port: int, db_name: str, username: str, password: str):
        super().__init__()
        self.client = MongoClient(f'mongodb://{str(ip)}:{port}/', username=username, password=password)
        self.db_name = db_name

        if self._collection_name not in self.client[self.db_name].list_collection_names():
            raise CollectionIsNotInitialized(
                f"Collection '{self.db_name}' is not initialized in database '{self.db_name}'")

    def add(self, item: Item):
        collection = self._item_collection()
        collection.insert_one(dict(MongoDBItem.from_domain_item(item)))

    def get(self, item_id: UUID) -> Optional[Item]:
        collection = self._item_collection()
        item: Optional[Dict] = collection.find_one({'uuid': item_id})
        if item is None:
            return None
        return MongoDBItem(**item).to_domain_item()

    def delete(self, item_id: UUID):
        collection = self._item_collection()
        collection.delete_one({'uuid': item_id})

    def get_by_subscription_id(self, subscription_id: UUID) -> List[Item]:
        collection = self._item_collection()
        items: Cursor[Any] = collection.find({'subscription_uuid': subscription_id}) \
            .sort('created_at', pymongo.DESCENDING)
        return [MongoDBItem(**item).to_domain_item() for item in items]

    def find(self, item: Item) -> Optional[Item]:
        collection = self._item_collection()
        db_item: Optional[Dict] = collection.find_one({'url': item.url})
        if db_item is None:
            return None
        return MongoDBItem(**db_item).to_domain_item()

    def find_sorted_by_publish_date(
            self,
            sub_ids: List[UUID],
            published_after: datetime,
            created_before: datetime,
            max_results: int,
            page_number: int
    ) -> Tuple[List[Item], int]:
        collection = self._item_collection()

        total_items: int = collection.count_documents({
            'subscription_uuid': {'$in': sub_ids},
            'published_at': {'$gt': published_after},
            'created_at': {'$lt': created_before}})

        items: Cursor[Any] = collection.find({
            'subscription_uuid': {'$in': sub_ids},
            'published_at': {'$gt': published_after},
            'created_at': {'$lt': created_before}
        }).sort(
            'published_at', pymongo.DESCENDING
        ).skip(
            page_number * max_results
        ).limit(
            max_results)

        return [MongoDBItem(**item).to_domain_item() for item in items], total_items

    def _item_collection(self) -> pymongo.collection.Collection:
        codec_options = CodecOptions(tz_aware=True, uuid_representation=UuidRepresentation.STANDARD)  # type: ignore
        return self.client.get_database(self.db_name).get_collection(
            self._collection_name,
            codec_options=codec_options)
