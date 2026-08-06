"""REST auth in multi-tenant (OAuth) mode: an OAuth access token must
resolve to the right tenant and never anyone else's, and the deprecated
static token must no longer work at all now that OAuth is live (retired
after being confirmed working end to end -- see docs/ADR-002).

Sets OAuth env vars before importing atlas_mcp.app, so run this as its own
process (python tests/test_rest_auth.py), not imported alongside other
tests that need OAuth off.
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

d = tempfile.mkdtemp()
os.environ["ATLAS_ROOT"] = d
os.environ["ATLAS_PUBLIC_URL"] = "https://atlas.example.com"
os.environ["ATLAS_GITHUB_CLIENT_ID"] = "test-client-id"
os.environ["ATLAS_GITHUB_CLIENT_SECRET"] = "test-secret"
os.environ["ATLAS_GITHUB_ALLOWED_USER"] = "owner"
os.environ["ATLAS_TOKEN"] = "test-static-token"
os.environ["ATLAS_GIT"] = "0"

from starlette.testclient import TestClient
from mcp.server.auth.provider import AccessToken

import atlas_mcp.app as appmod
from atlas_mcp.store import Project, new_project_body
from atlas_mcp.tenants import get_store_for

client = TestClient(appmod.app)


def _seed(username: str, project_id: str) -> None:
    s = get_store_for(username, appmod.ATLAS_ROOT, git=False, max_sensitivity="internal")
    s.save(Project(id=project_id, meta={"name": project_id}, body=new_project_body("test fixture")))


def test_static_token_rejected_in_oauth_mode():
    _seed("owner", "owner-project")
    resp = client.get("/api/projects", headers={"Authorization": "Bearer test-static-token"})
    assert resp.status_code == 401, resp.text
    print("static token rejected once OAuth is live: OK")


def test_oauth_token_resolves_own_tenant_and_is_isolated():
    _seed("alice", "alice-secret")
    fake_token = "fake-alice-access-token"
    appmod.oauth_provider._access_tokens[fake_token] = AccessToken(
        token=fake_token,
        client_id="test-client",
        scopes=["mcp"],
        expires_at=int(time.time()) + 3600,
        subject="alice",
    )
    resp = client.get("/api/projects", headers={"Authorization": f"Bearer {fake_token}"})
    assert resp.status_code == 200, resp.text
    ids = [p["id"] for p in resp.json()]
    assert "alice-secret" in ids, ids
    assert "owner-project" not in ids, "alice's REST session must not see the owner's tenant"
    print("oauth token -> own tenant, isolated: OK")


def test_bad_token_rejected():
    resp = client.get("/api/projects", headers={"Authorization": "Bearer nonsense"})
    assert resp.status_code == 401, resp.status_code
    resp = client.get("/api/projects")
    assert resp.status_code == 401, resp.status_code
    print("missing/bad token rejected: OK")


with client:
    test_static_token_rejected_in_oauth_mode()
    test_oauth_token_resolves_own_tenant_and_is_isolated()
    test_bad_token_rejected()
