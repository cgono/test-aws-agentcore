from collections.abc import Mapping
from dataclasses import dataclass


class SettingsError(ValueError):
    """Raised when POC configuration is missing or invalid."""


_FIELD_NAMES = (
    "aws_region",
    "aws_budget_name",
    "entra_tenant_id",
    "entra_public_client_id",
    "entra_api_client_id",
    "entra_downstream_scope",
    "agentcore_workload_name",
    "agentcore_second_workload_name",
    "agentcore_microsoft_provider",
    "agentcore_google_provider",
    "resource_api_audience",
    "resource_api_url",
    "public_base_url",
)


@dataclass(frozen=True)
class Settings:
    aws_region: str
    aws_budget_name: str
    entra_tenant_id: str
    entra_public_client_id: str
    entra_api_client_id: str
    entra_downstream_scope: str
    agentcore_workload_name: str
    agentcore_second_workload_name: str
    agentcore_microsoft_provider: str
    agentcore_google_provider: str
    resource_api_audience: str
    resource_api_url: str
    public_base_url: str

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> "Settings":
        configured_values: dict[str, str] = {}
        for field_name in _FIELD_NAMES:
            environment_name = field_name.upper()
            value = values.get(environment_name)
            if not isinstance(value, str) or not value:
                raise SettingsError(f"{environment_name} must be set")

            value = value.rstrip("/")
            if not value:
                raise SettingsError(f"{environment_name} must be set")
            configured_values[field_name] = value

        public_base_url = configured_values["public_base_url"]
        if not public_base_url.startswith("https://"):
            raise SettingsError("PUBLIC_BASE_URL must use https")

        return cls(**configured_values)

    @property
    def entra_issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"

    @property
    def google_return_url(self) -> str:
        return f"{self.public_base_url}/oauth/google/return"
