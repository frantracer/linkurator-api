from typing import List
from uuid import UUID

from linkurator_core.application.exceptions import UserNotFoundError
from linkurator_core.domain.topic import Topic
from linkurator_core.domain.topic_repository import TopicRepository
from linkurator_core.domain.user_repository import UserRepository


class GetUserTopicsHandler:
    def __init__(self, user_repo: UserRepository, topic_repo: TopicRepository):
        self.user_repo = user_repo
        self.topic_repo = topic_repo

    def handle(self, user_id: UUID) -> List[Topic]:
        user = self.user_repo.get(user_id)
        if user is None:
            raise UserNotFoundError(user_id)

        return self.topic_repo.get_by_user_id(user_id)
