from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse


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

            value = value.strip().rstrip("/")
            if not value:
                raise SettingsError(f"{environment_name} must be set")
            configured_values[field_name] = value

        public_base_url = configured_values["public_base_url"]
        try:
            parsed_public_base_url = urlparse(public_base_url)
        except ValueError as error:
            raise SettingsError("PUBLIC_BASE_URL must use https") from error

        if (
            parsed_public_base_url.scheme != "https"
            or not parsed_public_base_url.netloc
            or parsed_public_base_url.params
            or parsed_public_base_url.query
            or parsed_public_base_url.fragment
        ):
            raise SettingsError("PUBLIC_BASE_URL must use https")

        return cls(**configured_values)

    @property
    def entra_issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.entra_tenant_id}/v2.0"

    @property
    def google_return_url(self) -> str:
        return f"{self.public_base_url}/oauth/google/return"
