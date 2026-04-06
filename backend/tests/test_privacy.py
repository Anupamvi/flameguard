from app.privacy import (
    REDACTED_RESOURCE_GROUP,
    REDACTED_SUBSCRIPTION,
    sanitize_azure_data,
    sanitize_azure_text,
)


def test_sanitize_azure_text_redacts_arm_segments() -> None:
    raw = "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/prod-networking/providers/Microsoft.Network/networkSecurityGroups/example"

    sanitized = sanitize_azure_text(raw)

    assert "11111111-2222-3333-4444-555555555555" not in sanitized
    assert "prod-networking" not in sanitized
    assert REDACTED_SUBSCRIPTION in sanitized
    assert REDACTED_RESOURCE_GROUP in sanitized


def test_sanitize_azure_data_redacts_nested_fields() -> None:
    payload = {
        "subscriptionId": "11111111-2222-3333-4444-555555555555",
        "resourceGroup": "prod-networking",
        "properties": {
            "resourceGroupName": "prod-networking",
            "id": "/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/prod-networking/providers/Microsoft.Network/publicIPAddresses/example",
        },
    }

    sanitized = sanitize_azure_data(payload)

    assert sanitized["subscriptionId"] == REDACTED_SUBSCRIPTION
    assert sanitized["resourceGroup"] == REDACTED_RESOURCE_GROUP
    assert sanitized["properties"]["resourceGroupName"] == REDACTED_RESOURCE_GROUP
    assert REDACTED_SUBSCRIPTION in sanitized["properties"]["id"]
    assert REDACTED_RESOURCE_GROUP in sanitized["properties"]["id"]
