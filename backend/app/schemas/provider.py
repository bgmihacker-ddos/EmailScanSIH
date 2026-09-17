from typing import TypedDict, List, Optional, Any

class ProviderResponse(TypedDict):
    data: List[Any]
    status: str
    error_message: Optional[str]
