"""Fail-closed runtime assembly for the PaperDesk watchdog WSGI provider."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Mapping

from provider.watchdog_state_provider import (
    APP_NAME,
    BASELINE_ENVIRONMENT,
    BASELINE_WORKFLOW_REF,
    EVIDENCE_CONTAINER,
    GithubAppDispatcher,
    ManagedIdentityTokens,
    OIDCVerifier,
    ProviderError,
    REGISTRY_CONTAINER,
    STATE_CONTAINER,
    STORAGE_ACCOUNT,
    STORAGE_RESOURCE_GROUP,
    AzureIdentityBinding,
    AzureStorageBackend,
    WatchdogProvider,
    fail,
    jwt_module,
)
from scripts import watchdog_contract


UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
POSITIVE = re.compile(r"^[1-9][0-9]*$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTITY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


@dataclass(frozen=True)
class ProviderConfig:
    subscription_id: str
    identity_bindings: Mapping[str, AzureIdentityBinding]
    watchdog_workflow_sha: str
    baseline_workflow_sha: str
    reconciliation_workflow_sha: str
    control_workflow_sha: str
    package_sha256: str
    github_app_id: str
    github_app_installation_id: str
    github_app_private_key_pem: str
    machine_contract: Mapping[str, Any]

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str],
        machine_contract: Mapping[str, Any] | None = None,
    ) -> "ProviderConfig":
        machine = machine_contract or watchdog_contract.load_contract()
        if str(environment.get("WEBSITE_SITE_NAME") or "").lower() != APP_NAME:
            fail("provider is not running in the exact approved App Service", 500, "provider-site-invalid")
        subscription_id = str(environment.get("PAPERDESK_WATCHDOG_AZURE_SUBSCRIPTION_ID") or "")
        if not UUID.fullmatch(subscription_id):
            fail("provider Azure subscription coordinate is invalid", 500, "provider-config-invalid")
        names = {
            "watchdog_workflow_sha": "PAPERDESK_WATCHDOG_ALLOWED_WORKFLOW_SHA",
            "baseline_workflow_sha": "PAPERDESK_WATCHDOG_ALLOWED_BASELINE_WORKFLOW_SHA",
            "reconciliation_workflow_sha": "PAPERDESK_WATCHDOG_ALLOWED_RECONCILIATION_WORKFLOW_SHA",
            "control_workflow_sha": "PAPERDESK_WATCHDOG_CONTROL_WORKFLOW_SHA",
        }
        hashes = {name: str(environment.get(variable) or "") for name, variable in names.items()}
        if any(not SHA40.fullmatch(value) for value in hashes.values()):
            fail("provider workflow SHA allowlists are invalid", 500, "provider-config-invalid")
        package_sha256 = str(environment.get("PAPERDESK_WATCHDOG_PACKAGE_SHA256") or "")
        if not SHA256.fullmatch(package_sha256):
            fail("provider package digest is invalid", 500, "provider-config-invalid")
        reviewed_control = machine.get("immutableExternalControl", {}).get("mergedMutatingCommitSha")
        if reviewed_control is None:
            fail("immutable external control activation remains dormant", 503, "activation-dormant")
        if reviewed_control != hashes["control_workflow_sha"]:
            fail("provider control workflow SHA differs from the independently merged contract", 500, "provider-config-invalid")

        account_scope = (
            f"/subscriptions/{subscription_id}/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/"
            f"Microsoft.Storage/storageAccounts/{STORAGE_ACCOUNT}"
        )
        coordinates = {
            "state-read-write": (
                "STATE", f"{account_scope}/blobServices/default/containers/{STATE_CONTAINER}",
            ),
            "evidence-create-only": (
                "EVIDENCE_WRITER", f"{account_scope}/blobServices/default/containers/{EVIDENCE_CONTAINER}",
            ),
            "evidence-read-only": (
                "EVIDENCE_READER", f"{account_scope}/blobServices/default/containers/{EVIDENCE_CONTAINER}",
            ),
            "registry-read-only": (
                "REGISTRY_READER", f"{account_scope}/blobServices/default/containers/{REGISTRY_CONTAINER}",
            ),
            "arm-policy-read-only": ("POLICY_READER", f"/subscriptions/{subscription_id}"),
        }
        identity_prefix = (
            f"/subscriptions/{subscription_id}/resourceGroups/{STORAGE_RESOURCE_GROUP}/providers/"
            "Microsoft.ManagedIdentity/userAssignedIdentities/"
        )
        bindings: dict[str, AzureIdentityBinding] = {}
        for role, (prefix, scope) in coordinates.items():
            client_id = str(environment.get(f"PAPERDESK_WATCHDOG_{prefix}_IDENTITY_CLIENT_ID") or "")
            principal_id = str(environment.get(f"PAPERDESK_WATCHDOG_{prefix}_IDENTITY_PRINCIPAL_ID") or "")
            identity_resource_id = str(environment.get(f"PAPERDESK_WATCHDOG_{prefix}_IDENTITY_RESOURCE_ID") or "")
            assignment_id = str(environment.get(f"PAPERDESK_WATCHDOG_{prefix}_ROLE_ASSIGNMENT_ID") or "")
            definition_id = str(environment.get(f"PAPERDESK_WATCHDOG_{prefix}_ROLE_DEFINITION_ID") or "")
            if any(not UUID.fullmatch(value) for value in (client_id, principal_id, assignment_id, definition_id)):
                fail(f"provider {role} identity coordinates are invalid", 500, "provider-config-invalid")
            suffix = identity_resource_id[len(identity_prefix):] if identity_resource_id.startswith(identity_prefix) else ""
            if not IDENTITY_NAME.fullmatch(suffix):
                fail(f"provider {role} identity resource is invalid", 500, "provider-config-invalid")
            bindings[role] = AzureIdentityBinding(
                role, client_id, principal_id, identity_resource_id,
                assignment_id, definition_id, scope,
            )
        for attribute in ("client_id", "principal_id", "identity_resource_id", "assignment_id"):
            if len({getattr(binding, attribute) for binding in bindings.values()}) != 5:
                fail("provider five identity bindings and assignments must be distinct", 500, "provider-config-invalid")

        app_id = environment.get("PAPERDESK_WATCHDOG_GITHUB_APP_ID")
        installation_id = environment.get("PAPERDESK_WATCHDOG_GITHUB_APP_INSTALLATION_ID")
        private_key = environment.get("PAPERDESK_WATCHDOG_GITHUB_APP_PRIVATE_KEY_PEM")
        app_values = (app_id, installation_id, private_key)
        if not any(app_values):
            fail(
                "provider GitHub App configuration is required for active control",
                500,
                "provider-config-invalid",
            )
        if any(app_values) and not all(app_values):
            fail("provider GitHub App configuration is partial", 500, "provider-config-invalid")
        if app_id is not None and (not isinstance(app_id, str) or not POSITIVE.fullmatch(app_id) or len(app_id) > 20):
            fail("provider GitHub App ID is invalid", 500, "provider-config-invalid")
        if installation_id is not None and (
            not isinstance(installation_id, str)
            or not POSITIVE.fullmatch(installation_id)
            or len(installation_id) > 20
        ):
            fail("provider GitHub App installation ID is invalid", 500, "provider-config-invalid")
        if private_key is not None and (
            not isinstance(private_key, str) or not 256 <= len(private_key) <= 32768
        ):
            fail("provider GitHub App private key is invalid", 500, "provider-config-invalid")
        return cls(
            subscription_id=subscription_id,
            identity_bindings=bindings,
            package_sha256=package_sha256,
            github_app_id=str(app_id),
            github_app_installation_id=str(installation_id),
            github_app_private_key_pem=str(private_key),
            machine_contract=machine,
            **hashes,
        )


def build_identity_clients(
    config: ProviderConfig,
    environment: Mapping[str, str],
) -> dict[str, tuple[ManagedIdentityTokens, AzureIdentityBinding]]:
    return {
        role: (ManagedIdentityTokens(binding.client_id, environment), binding)
        for role, binding in config.identity_bindings.items()
    }


class ProviderOIDCVerifier(OIDCVerifier):
    """Cryptographically verify both provider workflows and five CAS callers."""

    def __init__(self, config: ProviderConfig, **kwargs: Any):
        super().__init__(
            config.watchdog_workflow_sha,
            config.baseline_workflow_sha,
            reconciliation_workflow_sha=config.reconciliation_workflow_sha,
            **kwargs,
        )
        self.config = config
        self.machine = config.machine_contract

    def _decode_all_claims(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token or len(token) > 32768 or token.count(".") != 2:
            fail("GitHub OIDC bearer token is invalid", 401, "oidc-invalid")
        jwt = jwt_module()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            fail("GitHub OIDC bearer token is invalid", 401, "oidc-invalid")
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            fail("GitHub OIDC header is invalid", 401, "oidc-invalid")
        jwk = self._load_keys().get(header["kid"])
        if jwk is None:
            fail("GitHub OIDC signature key is not current", 401, "oidc-invalid")
        try:
            public_key = jwt.PyJWK.from_dict(jwk, algorithm="RS256").key
            claims = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=self.machine["provider"]["audience"],
                issuer=self.machine["provider"]["issuer"],
                leeway=30,
                options={
                    "require": self.machine["oidc"]["requiredClaims"],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_exp": True,
                },
            )
        except (jwt.PyJWTError, TypeError, ValueError):
            fail("GitHub OIDC signature or claims are invalid", 401, "oidc-invalid")
        if not isinstance(claims, dict):
            fail("GitHub OIDC claims are invalid", 401, "oidc-invalid")
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() != timedelta(0):
            fail("provider clock is invalid", 500, "provider-clock-invalid")
        epoch = int(now.timestamp())
        if (
            any(type(claims.get(name)) is not int for name in ("iat", "nbf", "exp"))
            or claims["iat"] > epoch + 30
            or claims["nbf"] > epoch + 30
            or claims["exp"] <= epoch
            or claims["exp"] <= claims["iat"]
            or claims["exp"] - claims["iat"] > 900
            or claims["exp"] <= claims["nbf"]
        ):
            fail("GitHub OIDC lifetime is invalid", 401, "oidc-invalid")
        return claims

    def _control_job(self, claims: Mapping[str, Any]) -> None:
        expected = (
            f"{self.machine['immutableExternalControl']['repository']}/"
            f"{self.machine['immutableExternalControl']['workflowPath']}@"
            f"{self.config.control_workflow_sha}"
        )
        if (
            claims.get("job_workflow_ref") != expected
            or claims.get("job_workflow_sha") != self.config.control_workflow_sha
        ):
            fail("GitHub OIDC job is not the reviewed immutable control", 403, "oidc-forbidden")

    def verify_transition(self, token: str, request: Mapping[str, Any]) -> dict[str, Any]:
        claims = self._decode_all_claims(token)
        try:
            watchdog_contract.validate_oidc_binding(self.machine, request, claims)
        except ValueError as exc:
            fail(str(exc), 403, "oidc-forbidden")
        self._control_job(claims)
        return claims

    def verify_state(self, token: str) -> dict[str, Any]:
        try:
            return super().verify(token, "state")
        except ProviderError as exc:
            if exc.status != 403 or exc.code != "oidc-forbidden":
                raise
        claims = self._decode_all_claims(token)
        source = self.machine["sourceRepository"]
        expected = {
            "repository": source["repository"],
            "repository_id": source["repositoryId"],
            "repository_owner": source["repositoryOwner"],
            "repository_owner_id": source["repositoryOwnerId"],
            "ref": source["ref"],
            "environment": self.machine["oidc"]["environment"],
            "sub": self.machine["oidc"]["subject"],
        }
        if any(str(claims.get(name) or "") != str(value) for name, value in expected.items()):
            fail("GitHub OIDC state caller identity is not exact", 403, "oidc-forbidden")
        allowed = {
            f"{source['repository']}/{transition['callerWorkflow']}@{source['ref']}"
            for transition in self.machine["transitions"].values()
        }
        if claims.get("workflow_ref") not in allowed or claims.get("sha") != claims.get("workflow_sha"):
            fail("GitHub OIDC state caller workflow is not exact", 403, "oidc-forbidden")
        self._control_job(claims)
        return claims

    def verify_internal(self, token: str, purpose: str) -> dict[str, Any]:
        if purpose == "baseline":
            return super().verify(token, "evidence")
        return super().verify(token, purpose)


def build_runtime(environment: Mapping[str, str]) -> tuple[ProviderOIDCVerifier, WatchdogProvider]:
    config = ProviderConfig.from_environment(environment)
    identities = build_identity_clients(config, environment)
    storage = AzureStorageBackend(config.subscription_id, identities)
    dispatcher = GithubAppDispatcher(
        config.github_app_id,
        config.github_app_installation_id,
        config.github_app_private_key_pem,
    )
    verifier = ProviderOIDCVerifier(config)
    service = WatchdogProvider(
        storage,
        dispatcher,
        contract=config.machine_contract,
    )
    return verifier, service


__all__ = [
    "ProviderConfig", "ProviderError", "ProviderOIDCVerifier", "build_identity_clients",
    "build_runtime",
]
