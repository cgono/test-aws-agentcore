from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
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


def _is_alternate_ipv4_literal(hostname: str) -> bool:
    labels = hostname.split(".")
    return len(labels) == 4 and all(
        label.isdecimal()
        or (
            label.lower().startswith("0x")
            and len(label) > 2
            and all(character in "0123456789abcdef" for character in label[2:].lower())
        )
        for label in labels
    )


def _is_public_callback_hostname(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return False

    if _is_alternate_ipv4_literal(hostname):
        return False

    try:
        return ip_address(hostname).is_global
    except ValueError:
        try:
            idna_hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            return False

    labels = idna_hostname.split(".")
    return len(labels) >= 2 and all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and all(
            character.isascii() and (character.isalnum() or character == "-")
            for character in label
        )
        for label in labels
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
            hostname = parsed_public_base_url.hostname
            port = parsed_public_base_url.port
        except ValueError as error:
            raise SettingsError("PUBLIC_BASE_URL must use https") from error

        if (
            parsed_public_base_url.scheme != "https"
            or not hostname
            or not (port is None or 1 <= port <= 65535)
            or parsed_public_base_url.username is not None
            or parsed_public_base_url.password is not None
            or not _is_public_callback_hostname(hostname)
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
