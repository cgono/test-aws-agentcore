import pytest

from agentcore_identity_poc.config import Settings, SettingsError

BASE = {
    "AWS_REGION": "us-west-2",
    "AWS_BUDGET_NAME": "agentcore-identity-poc-monthly",
    "ENTRA_TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "ENTRA_PUBLIC_CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "ENTRA_API_CLIENT_ID": "33333333-3333-3333-3333-333333333333",
    "ENTRA_DOWNSTREAM_SCOPE": "api://44444444-4444-4444-4444-444444444444/access_as_user",
    "AGENTCORE_WORKLOAD_NAME": "iig-poc-approved",
    "AGENTCORE_SECOND_WORKLOAD_NAME": "iig-poc-unapproved",
    "AGENTCORE_MICROSOFT_PROVIDER": "iig-poc-microsoft",
    "AGENTCORE_GOOGLE_PROVIDER": "iig-poc-google",
    "RESOURCE_API_AUDIENCE": "api://44444444-4444-4444-4444-444444444444",
    "RESOURCE_API_URL": "https://poc-resource.example.test/metadata",
    "PUBLIC_BASE_URL": "https://poc-callback.example.test",
}


def test_settings_require_exact_https_public_url() -> None:
    values = BASE | {"PUBLIC_BASE_URL": "http://localhost:8000"}

    with pytest.raises(SettingsError, match="PUBLIC_BASE_URL must use https"):
        Settings.from_mapping(values)


def test_settings_derive_pinned_issuer_and_callback() -> None:
    settings = Settings.from_mapping(BASE)

    assert (
        settings.entra_issuer
        == "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"
    )
    assert settings.google_return_url == "https://poc-callback.example.test/oauth/google/return"


def test_settings_require_nonempty_values() -> None:
    values = BASE | {"ENTRA_TENANT_ID": ""}

    with pytest.raises(SettingsError, match="ENTRA_TENANT_ID"):
        Settings.from_mapping(values)


def test_settings_strip_trailing_slashes() -> None:
    values = {name: f"{value}/" for name, value in BASE.items()}
    settings = Settings.from_mapping(values)

    assert settings.aws_region == "us-west-2"
    assert settings.public_base_url == "https://poc-callback.example.test"
