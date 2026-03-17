"""
Analytics system for game events
Separate from logging system - focused on game metrics and player behavior
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from enum import Enum

import boto3
from botocore.exceptions import ClientError

from config import config
from logger import logger


class EventType(Enum):
    """Game event types"""
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    LEVEL_START = "level_start"
    LEVEL_COMPLETE = "level_complete"
    LEVEL_FAIL = "level_fail"
    ACHIEVEMENT_UNLOCK = "achievement_unlock"
    SKILL_UPGRADE = "skill_upgrade"
    DUST_COLLECTED = "dust_collected"
    ENEMY_KILLED = "enemy_killed"
    PLAYER_DEATH = "player_death"
    LEADERBOARD_SUBMIT = "leaderboard_submit"
    NFT_MINT = "nft_mint"
    CUSTOM = "custom"


class AnalyticsService:
    """
    Analytics service for tracking game events
    
    Table Schema:
        event_id (PK) - UUID
        timestamp (SK) - ISO timestamp
        user_id - User identifier
        event_type - Type of event
        event_data - JSON event data
        session_id - Session identifier
        platform - web/ios/android
        app_version - Game version
        ttl - Expiration timestamp
    
    GSI Indexes:
        - UserEventsIndex: user_id (PK), timestamp (SK)
        - EventTypeIndex: event_type (PK), timestamp (SK)
        - SessionEventsIndex: session_id (PK), timestamp (SK)
    """
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb', region_name=config.AWS_REGION)
        self.table = self.dynamodb.Table(config.TABLE_ANALYTICS)
    
    def track_event(
        self,
        user_id: str,
        event_type: EventType,
        event_data: Dict[str, Any],
        session_id: Optional[str] = None,
        platform: Optional[str] = None,
        app_version: Optional[str] = None,
        raw_event_type: Optional[str] = None,
        wallet_id: Optional[str] = None,
        client_timestamp: Optional[str] = None
    ) -> bool:
        """
        Track a game event

        Args:
            user_id: User identifier (JWT user_id)
            event_type: Normalised EventType enum value
            event_data: Event-specific data dict
            session_id: Session identifier
            platform: Platform (web/ios/android)
            app_version: Game version string
            raw_event_type: Original event type string from client (e.g. "GameStart")
            wallet_id: Wallet address sent by client (may differ from user_id)
            client_timestamp: ISO timestamp generated on the client side

        Returns:
            Success status
        """
        try:
            logger.info(f"Tracking analytics event: {event_type.value}", context={
                "user_id": user_id,
                "event_type": event_type.value,
                "session_id": session_id,
                "platform": platform
            })
            
            now = datetime.now(timezone.utc)
            event_id = str(uuid.uuid4())
            
            # Calculate TTL (90 days retention for analytics)
            ttl = int(now.timestamp()) + (90 * 86400)

            def _sanitize(obj):
                """Recursively convert float -> Decimal for DynamoDB compatibility."""
                from decimal import Decimal
                if isinstance(obj, float):
                    return Decimal(str(obj))
                if isinstance(obj, dict):
                    return {k: _sanitize(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_sanitize(v) for v in obj]
                return obj

            item = {
                "event_id": event_id,
                "timestamp": int(now.timestamp() * 1000),  # Unix timestamp in milliseconds
                "created_at": now.isoformat(),  # ISO string for readability
                "user_id": user_id,
                "event_type": event_type.value,
                "event_data": _sanitize(event_data),
                "ttl": ttl
            }
            
            if session_id:
                item["session_id"] = session_id

            if platform:
                item["platform"] = platform

            if app_version:
                item["app_version"] = app_version

            # Preserve original client-side event type string for backoffice queries
            if raw_event_type and raw_event_type != event_type.value:
                item["raw_event_type"] = raw_event_type

            if wallet_id:
                item["wallet_id"] = wallet_id

            if client_timestamp:
                item["client_timestamp"] = client_timestamp

            self.table.put_item(Item=item)
            
            logger.debug(
                f"Analytics event tracked: {event_type.value}",
                context={"event_id": event_id, "user_id": user_id}
            )
            
            return True
        
        except ClientError as e:
            logger.error(
                f"Failed to track analytics event: {event_type.value}",
                context={"user_id": user_id, "event_type": event_type.value},
                error=e
            )
            return False
        except Exception as e:
            logger.error(
                f"Unexpected error tracking analytics event",
                context={"user_id": user_id, "event_type": event_type.value},
                error=e
            )
            return False
    
    def get_user_events(
        self,
        user_id: str,
        event_type: Optional[EventType] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get events for a specific user"""
        try:
            logger.debug("Querying user events", context={"user_id": user_id, "event_type": event_type.value if event_type else None, "limit": limit})
            query_params = {
                "IndexName": "UserEventsIndex",
                "KeyConditionExpression": "user_id = :user_id",
                "ExpressionAttributeValues": {":user_id": user_id},
                "ScanIndexForward": False,
            }

            # Add time range filter.
            # timestamp SK is stored as Unix milliseconds (int) — compare with int, not ISO string.
            if start_time or end_time:
                conditions = []
                if start_time:
                    conditions.append("#ts >= :start")
                    query_params["ExpressionAttributeValues"][":start"] = int(start_time.timestamp() * 1000)
                if end_time:
                    conditions.append("#ts <= :end")
                    query_params["ExpressionAttributeValues"][":end"] = int(end_time.timestamp() * 1000)

                if conditions:
                    query_params["ExpressionAttributeNames"] = {"#ts": "timestamp"}
                    query_params["KeyConditionExpression"] += " AND " + " AND ".join(conditions)

            # Add event type filter.
            # FilterExpression is evaluated AFTER DynamoDB scans each page, so we must NOT set
            # a hard Limit at the DynamoDB level — otherwise we'd silently return fewer results
            # than requested. Instead we paginate until we collect `limit` matching items.
            if event_type:
                query_params["FilterExpression"] = "event_type = :event_type"
                query_params["ExpressionAttributeValues"][":event_type"] = event_type.value

                all_events: List[Dict] = []
                while True:
                    response = self.table.query(**query_params)
                    all_events.extend(response.get("Items", []))
                    if len(all_events) >= limit or "LastEvaluatedKey" not in response:
                        break
                    query_params["ExclusiveStartKey"] = response["LastEvaluatedKey"]

                events = all_events[:limit]
            else:
                # No filter expression — Limit is safe here
                query_params["Limit"] = limit
                response = self.table.query(**query_params)
                events = response.get("Items", [])

            logger.debug("User events retrieved", context={"user_id": user_id, "count": len(events)})
            return events

        except ClientError as e:
            logger.error(f"Failed to query user events", context={"user_id": user_id}, error=e)
            return []
    
    def get_session_events(self, session_id: str) -> List[Dict]:
        """Get all events for a specific session"""
        try:
            response = self.table.query(
                IndexName="SessionEventsIndex",
                KeyConditionExpression="session_id = :session_id",
                ExpressionAttributeValues={":session_id": session_id},
                ScanIndexForward=True
            )
            return response.get("Items", [])
        
        except ClientError as e:
            logger.error(f"Failed to query session events", context={"session_id": session_id}, error=e)
            return []
    
    def get_aggregated_stats(self, user_id: str, days: int = 7) -> Dict[str, Any]:
        """
        Get aggregated statistics for a user
        
        Returns metrics like:
        - Total sessions
        - Total playtime
        - Total kills
        - Total dust collected
        - Achievement progress
        """
        from datetime import timedelta
        
        start_time = datetime.now(timezone.utc) - timedelta(days=days)
        events = self.get_user_events(user_id, start_time=start_time, limit=1000)
        
        stats = {
            "user_id": user_id,
            "period_days": days,
            "total_events": len(events),
            "sessions": 0,
            "total_kills": 0,
            "total_dust": 0,
            "achievements_unlocked": 0,
            "levels_completed": 0,
            "deaths": 0
        }
        
        for event in events:
            event_type = event.get("event_type")
            event_data = event.get("event_data", {})
            
            if event_type == EventType.SESSION_START.value:
                stats["sessions"] += 1
            
            elif event_type == EventType.ENEMY_KILLED.value:
                stats["total_kills"] += event_data.get("count", 1)
            
            elif event_type == EventType.DUST_COLLECTED.value:
                stats["total_dust"] += event_data.get("amount", 0)
            
            elif event_type == EventType.ACHIEVEMENT_UNLOCK.value:
                stats["achievements_unlocked"] += 1
            
            elif event_type == EventType.LEVEL_COMPLETE.value:
                stats["levels_completed"] += 1
            
            elif event_type == EventType.PLAYER_DEATH.value:
                stats["deaths"] += 1
        
        return stats


# Convenience functions for common events

def track_session_start(user_id: str, session_id: str, platform: str, app_version: str) -> bool:
    """Track session start"""
    analytics = AnalyticsService()
    return analytics.track_event(
        user_id=user_id,
        event_type=EventType.SESSION_START,
        event_data={
            "device_info": platform
        },
        session_id=session_id,
        platform=platform,
        app_version=app_version
    )


def track_session_end(
    user_id: str,
    session_id: str,
    duration_seconds: int,
    end_reason: str,
    final_score: int
) -> bool:
    """Track session end"""
    analytics = AnalyticsService()
    return analytics.track_event(
        user_id=user_id,
        event_type=EventType.SESSION_END,
        event_data={
            "duration_seconds": duration_seconds,
            "end_reason": end_reason,
            "final_score": final_score
        },
        session_id=session_id
    )


def track_achievement(user_id: str, achievement_id: str, session_id: Optional[str] = None) -> bool:
    """Track achievement unlock"""
    analytics = AnalyticsService()
    return analytics.track_event(
        user_id=user_id,
        event_type=EventType.ACHIEVEMENT_UNLOCK,
        event_data={
            "achievement_id": achievement_id
        },
        session_id=session_id
    )


def track_leaderboard_submit(
    user_id: str,
    score_type: str,
    score_value: int,
    rank: Optional[int] = None
) -> bool:
    """Track leaderboard submission"""
    analytics = AnalyticsService()
    return analytics.track_event(
        user_id=user_id,
        event_type=EventType.LEADERBOARD_SUBMIT,
        event_data={
            "score_type": score_type,
            "score_value": score_value,
            "rank": rank
        }
    )
