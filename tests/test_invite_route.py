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


def _stub_github(login, gh_id):
    async def fake(code, cid, secret, cb):
        return login, gh_id
    appmod.verify_github_code = fake
    import atlas_mcp.github_oauth as go
    go.verify_github_code = fake


def test_invite_refuses_leftover_tenant_directory_and_binds_id():
    from pathlib import Path
    leftover = Path(appmod.ATLAS_ROOT) / "tenants" / "mallory"
    leftover.mkdir(parents=True)
    (leftover / "old-note.md").write_text("former tenant data")
    token = appmod.invite_registry.create()
    _stub_github("mallory", 66)
    r = client.get(f"/oauth/github/callback?code=c&state={appmod.INVITE_STATE_PREFIX}{token}")
    assert r.status_code == 409, r.text
    assert appmod.invite_registry.is_valid(token), "refusal must not burn the invite"
    assert not appmod.tenant_registry.has("mallory")
    # an empty directory is fine; the tenant is recorded with its GitHub id
    (leftover / "old-note.md").unlink()
    r = client.get(f"/oauth/github/callback?code=c&state={appmod.INVITE_STATE_PREFIX}{token}")
    assert r.status_code == 200, r.text
    assert appmod.tenant_registry.is_allowed("mallory", 66)
    assert not appmod.tenant_registry.is_allowed("mallory", 67)
    print("invite refuses leftover tenant data, records GitHub id: OK")


def test_client_login_needs_consent_page_before_code():
    import asyncio
    from mcp.shared.auth import OAuthClientInformationFull
    from mcp.server.auth.provider import AuthorizationParams
    prov = appmod.oauth_provider
    c = OAuthClientInformationFull(client_id="cx", client_name="<b>Totally Claude</b>",
                                   redirect_uris=["https://attacker.example/cb"],
                                   token_endpoint_auth_method="none")
    url = asyncio.run(prov.authorize(c, AuthorizationParams(
        state="s", scopes=["mcp"], code_challenge="x" * 43,
        redirect_uri=c.redirect_uris[0], redirect_uri_provided_explicitly=True)))
    gh_state = parse_qs(urlparse(url).query)["state"][0]
    _stub_github("owner", 1)
    r = client.get(f"/oauth/github/callback?code=c&state={gh_state}")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"], r.status_code
    assert "attacker.example" in r.text and "&lt;b&gt;Totally Claude" in r.text, "client + redirect host shown, escaped"
    assert r.headers["x-frame-options"] == "DENY"
    assert not prov._auth_codes, "no code before the user clicks Authorize"
    nonce = r.text.split('name="nonce" value="')[1].split('"')[0]
    bad = client.post("/oauth/consent", data={"state": gh_state, "nonce": "nope"})
    assert bad.status_code == 403
    ok = client.post("/oauth/consent", data={"state": gh_state, "nonce": nonce})
    assert ok.status_code == 403, "a failed attempt consumes the pending login"
    print("client login shows consent page; no code without approval: OK")


def test_tools_do_not_block_the_event_loop():
    import inspect
    from atlas_mcp import server
    for name in ("atlas_list_projects", "atlas_get_project", "atlas_search",
                 "atlas_upsert_project", "atlas_append_entry", "atlas_overview"):
        tool = server.mcp._tool_manager.get_tool(name)
        assert inspect.iscoroutinefunction(tool.fn), f"{name} runs store I/O on the event loop"
    print("MCP tools offload store work to threads: OK")


with client:
    test_invite_redirect_uses_the_single_registered_callback()
    test_invalid_invite_rejected_before_ever_reaching_github()
    test_invite_refuses_leftover_tenant_directory_and_binds_id()
    test_client_login_needs_consent_page_before_code()
    test_tools_do_not_block_the_event_loop()
