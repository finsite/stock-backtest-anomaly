"""
Processor module for stock-backtest-anomaly detection.

Validates input messages and detects anomalies in historical data.
Anomalies might include sudden price/volume changes or statistical deviations.
"""

from typing import Any

from app.utils.setup_logger import setup_logger
from app.utils.types import ValidatedMessage
from app.utils.validate_data import validate_message_schema

logger = setup_logger(__name__)


def validate_input_message(message: dict[str, Any]) -> ValidatedMessage:
    """
    Validate the incoming raw message against the expected schema.

    Args:
        message (dict[str, Any]): The raw message payload.

    Returns:
        ValidatedMessage: A validated message object.

    Raises:
        ValueError: If the message format is invalid.
    """
    logger.debug("🔍 Validating message schema...")
    if not validate_message_schema(message):
        logger.error("❌ Invalid message schema: %s", message)
        raise ValueError("Invalid message format")
    return message  # type: ignore[return-value]


def detect_anomaly(message: ValidatedMessage) -> dict[str, Any]:
    """
    Detect anomalies in stock data using placeholder logic.

    This function can be extended with Z-score, moving average divergence,
    or ML-based anomaly detection in the future.

    Args:
        message (ValidatedMessage): The validated input data.

    Returns:
        dict[str, Any]: The enriched message with anomaly metadata.
    """
    symbol = message.get("symbol", "UNKNOWN")
    price = float(message.get("price", 0))
    volume = int(message.get("volume", 0))
    logger.info("🔎 Checking for anomalies in %s", symbol)

    # Placeholder: Flag large price or volume spikes
    is_anomaly = price > 500 or volume > 1_000_000

    anomaly_result = {
        "anomaly_detected": is_anomaly,
        "reason": "High price" if price > 500 else ("High volume" if volume > 1_000_000 else "None"),
    }

    logger.debug("📊 Anomaly check result: %s", anomaly_result)
    return {**message, **anomaly_result}
