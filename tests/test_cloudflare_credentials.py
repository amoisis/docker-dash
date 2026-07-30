"""Tests for Cloudflare credential loading."""
from unittest.mock import patch

import cloudflare_client


def test_credentials_are_read_from_environment(monkeypatch):
    monkeypatch.setenv("CF_API_TOKEN", "environment-token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "environment-account")

    with patch("cloudflare_client.cloudflare.Cloudflare") as cloudflare:
        client, account_id = cloudflare_client.get_cloudflare_client()

    cloudflare.assert_called_once_with(api_token="environment-token")
    assert client is cloudflare.return_value
    assert account_id == "environment-account"


def test_credentials_are_read_from_secret_files(monkeypatch, tmp_path):
    token_file = tmp_path / "api-token"
    account_file = tmp_path / "account-id"
    token_file.write_text("secret-token\n", encoding="utf-8")
    account_file.write_text("secret-account\n", encoding="utf-8")
    monkeypatch.delenv("CF_API_TOKEN", raising=False)
    monkeypatch.delenv("CF_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("CF_API_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("CF_ACCOUNT_ID_FILE", str(account_file))

    with patch("cloudflare_client.cloudflare.Cloudflare") as cloudflare:
        client, account_id = cloudflare_client.get_cloudflare_client()

    cloudflare.assert_called_once_with(api_token="secret-token")
    assert client is cloudflare.return_value
    assert account_id == "secret-account"


def test_environment_credentials_take_precedence_over_secret_files(monkeypatch, tmp_path):
    token_file = tmp_path / "api-token"
    account_file = tmp_path / "account-id"
    token_file.write_text("secret-token", encoding="utf-8")
    account_file.write_text("secret-account", encoding="utf-8")
    monkeypatch.setenv("CF_API_TOKEN", "environment-token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "environment-account")
    monkeypatch.setenv("CF_API_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("CF_ACCOUNT_ID_FILE", str(account_file))

    with patch("cloudflare_client.cloudflare.Cloudflare") as cloudflare:
        _, account_id = cloudflare_client.get_cloudflare_client()

    cloudflare.assert_called_once_with(api_token="environment-token")
    assert account_id == "environment-account"


def test_missing_credentials_return_none(monkeypatch, tmp_path):
    monkeypatch.delenv("CF_API_TOKEN", raising=False)
    monkeypatch.delenv("CF_ACCOUNT_ID", raising=False)
    monkeypatch.setenv("CF_API_TOKEN_FILE", str(tmp_path / "missing-token"))
    monkeypatch.setenv("CF_ACCOUNT_ID_FILE", str(tmp_path / "missing-account"))

    assert cloudflare_client.get_cloudflare_client() == (None, None)
