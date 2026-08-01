from fastapi import HTTPException


def bad_request(message: str = "Bad request.") -> HTTPException:
    return HTTPException(
        status_code=400,
        detail=message
    )


def unauthorized(message: str = "Unauthorized.") -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=message
    )


def forbidden(message: str = "Forbidden.") -> HTTPException:
    return HTTPException(
        status_code=403,
        detail=message
    )


def not_found(message: str = "Resource not found.") -> HTTPException:
    return HTTPException(
        status_code=404,
        detail=message
    )


def conflict(message: str = "Conflict.") -> HTTPException:
    return HTTPException(
        status_code=409,
        detail=message
    )


def payload_too_large(message: str = "Request body too large.") -> HTTPException:
    return HTTPException(
        status_code=413,
        detail=message
    )


def internal_server_error(
    message: str = "Internal server error. Please try again later."
) -> HTTPException:
    return HTTPException(
        status_code=500,
        detail=message
    )


def service_unavailable(
    message: str = "Service temporarily unavailable."
) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=message
    )