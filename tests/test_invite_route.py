"""Regression guard for a real bug hit in production: GitHub OAuth Apps
support exactly one registered callback URL. invite_start() must always
redirect through that same URL (GITHUB_CALLBACK_URL in app.py), never a
second one -- a mismatch gets silently rejected by GitHub itself
("the redirect_uri is not associated with this application") before our
code ever sees the request.
"""
import os, sys, tempfile
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["ATLAS_ROOT"] = tempfile.mkdtemp()
os.environ["ATLAS_PUBLIC_URL"] = "https://atlas.example.com"
os.environ["ATLAS_GITHUB_CLIENT_ID"] = "test-client-id"
os.environ["ATLAS_GITHUB_CLIENT_SECRET"] = "test-secret"
os.environ["ATLAS_GITHUB_ALLOWED_USER"] = "owner"
os.environ["ATLAS_TOKEN"] = "test-static-token"
os.environ["ATLAS_GIT"] = "0"

from starlette.testclient import TestClient

import atlas_mcp.app as appmod

client = TestClient(appmod.app, follow_redirects=False)


def test_invite_redirect_uses_the_single_registered_callback():
    token = appmod.invite_registry.create()
    resp = client.get(f"/invite/{token}")
    assert resp.status_code in (302, 303, 307), resp.status_code

    location = urlparse(resp.headers["location"])
    assert location.netloc == "github.com", location.netloc
    qs = parse_qs(location.query)

    # The one and only thing this test exists to pin: the invite flow's
    # redirect_uri must equal the MCP/REST client flow's, not a second URL.
    assert qs["redirect_uri"][0] == appmod.GITHUB_CALLBACK_URL, qs["redirect_uri"]
    assert qs["redirect_uri"][0] == f"{appmod.ATLAS_PUBLIC_URL}/oauth/github/callback"

    assert qs["state"][0].startswith(appmod.INVITE_STATE_PREFIX)
    print("invite redirect reuses the single registered GitHub callback: OK")


def test_invalid_invite_rejected_before_ever_reaching_github():
    resp = client.get("/invite/this-token-does-not-exist")
    assert resp.status_code == 404, resp.status_code
    assert "location" not in resp.headers
    print("unknown invite token rejected without a GitHub redirect: OK")


with client:
    test_invite_redirect_uses_the_single_registered_callback()
    test_invalid_invite_rejected_before_ever_reaching_github()
