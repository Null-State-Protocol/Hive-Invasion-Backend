"""
Input validation utilities
"""

from typing import Any, Dict, List, Optional, Tuple
from decimal import Decimal


class ValidationError(Exception):
    """Custom validation error"""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class Validator:
    """Input validation helper"""
    
    @staticmethod
    def required(data: Dict[str, Any], field: str) -> Any:
        """Check if field is present and not None"""
        if field not in data:
            raise ValidationError(field, "This field is required")
        
        value = data[field]
        if value is None:
            raise ValidationError(field, "This field cannot be null")
        
        if isinstance(value, str) and not value.strip():
            raise ValidationError(field, "This field cannot be empty")
        
        return value
    
    @staticmethod
    def optional(data: Dict[str, Any], field: str, default: Any = None) -> Any:
        """Get optional field with default value"""
        return data.get(field, default)
    
    @staticmethod
    def string(value: Any, field: str, min_length: int = 0, max_length: int = 10000) -> str:
        """Validate string"""
        if not isinstance(value, str):
            raise ValidationError(field, "Must be a string")
        
        if len(value) < min_length:
            raise ValidationError(field, f"Must be at least {min_length} characters")
        
        if len(value) > max_length:
            raise ValidationError(field, f"Must be at most {max_length} characters")
        
        return value
    
    @staticmethod
    def integer(value: Any, field: str, min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
        """Validate integer"""
        try:
            if isinstance(value, Decimal):
                value = int(value)
            elif isinstance(value, str):
                value = int(value)
            elif not isinstance(value, int):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError(field, "Must be an integer")
        
        if min_value is not None and value < min_value:
            raise ValidationError(field, f"Must be at least {min_value}")
        
        if max_value is not None and value > max_value:
            raise ValidationError(field, f"Must be at most {max_value}")
        
        return value
    
    @staticmethod
    def boolean(value: Any, field: str) -> bool:
        """Validate boolean"""
        if isinstance(value, bool):
            return value
        
        if isinstance(value, str):
            if value.lower() in ('true', '1', 'yes', 'on'):
                return True
            if value.lower() in ('false', '0', 'no', 'off'):
                return False
        
        if isinstance(value, (int, Decimal)):
            return bool(value)
        
        raise ValidationError(field, "Must be a boolean")
    
    @staticmethod
    def list_of(value: Any, field: str, item_type: type = str, max_items: int = 1000) -> list:
        """Validate list"""
        if not isinstance(value, list):
            raise ValidationError(field, "Must be a list")
        
        if len(value) > max_items:
            raise ValidationError(field, f"Must contain at most {max_items} items")
        
        for i, item in enumerate(value):
            if not isinstance(item, item_type):
                raise ValidationError(field, f"Item {i} must be of type {item_type.__name__}")
        
        return value
    
    @staticmethod
    def dict_of(value: Any, field: str, max_keys: int = 100) -> dict:
        """Validate dictionary"""
        if not isinstance(value, dict):
            raise ValidationError(field, "Must be a dictionary")
        
        if len(value) > max_keys:
            raise ValidationError(field, f"Must contain at most {max_keys} keys")
        
        return value
    
    @staticmethod
    def enum(value: Any, field: str, allowed_values: List[Any]) -> Any:
        """Validate enum value"""
        if value not in allowed_values:
            raise ValidationError(field, f"Must be one of: {', '.join(map(str, allowed_values))}")
        
        return value


def validate_request_body(body: Any) -> Dict[str, Any]:
    """Validate and parse request body"""
    if body is None:
        return {}
    
    if isinstance(body, str):
        import json
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            raise ValidationError("body", "Invalid JSON")
    
    if not isinstance(body, dict):
        raise ValidationError("body", "Request body must be a JSON object")
    
    return body


def validate_achievements(achievements: Dict[str, Any]) -> Dict[str, bool]:
    """Validate achievements structure"""
    if not isinstance(achievements, dict):
        raise ValidationError("achievements", "Must be a dictionary")
    
    from config import config
    if len(achievements) > config.MAX_ACHIEVEMENT_COUNT:
        raise ValidationError("achievements", f"Too many achievements (max {config.MAX_ACHIEVEMENT_COUNT})")
    
    validated = {}
    for key, value in achievements.items():
        if not isinstance(key, str):
            raise ValidationError("achievements", "Achievement keys must be strings")
        
        # Convert to boolean
        validated[key] = Validator.boolean(value, f"achievements.{key}")
    
    return validated


def validate_skill_locations(skill_locations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validate skill locations structure"""
    if not isinstance(skill_locations, list):
        raise ValidationError("skillLocations", "Must be a list")
    
    from config import config
    if len(skill_locations) > config.MAX_SKILL_LOCATIONS:
        raise ValidationError("skillLocations", f"Too many skill locations (max {config.MAX_SKILL_LOCATIONS})")
    
    validated = []
    for i, item in enumerate(skill_locations):
        if not isinstance(item, dict):
            raise ValidationError(f"skillLocations[{i}]", "Must be an object")
        
        skill = Validator.required(item, "skill")
        location = Validator.required(item, "location")
        
        skill = Validator.string(skill, f"skillLocations[{i}].skill", max_length=50)
        location = Validator.integer(location, f"skillLocations[{i}].location")
        
        validated.append({"skill": skill, "location": location})
    
    return validated
