"""REST auth with OAuth entirely disabled (no ATLAS_PUBLIC_URL/ATLAS_GITHUB_*
set): the static ATLAS_TOKEN must still be the sole, working credential --
this is a genuinely different, still-supported deployment mode, distinct
from the deprecated OAuth-mode static-token path that was retired (see
test_rest_auth.py).

Own process, same reason as test_rest_auth.py: OAuth mode is decided at
import time from env vars.
"""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

d = tempfile.mkdtemp()
os.environ["ATLAS_ROOT"] = d
os.environ["ATLAS_TOKEN"] = "test-static-token"
for var in ("ATLAS_PUBLIC_URL", "ATLAS_GITHUB_CLIENT_ID", "ATLAS_GITHUB_CLIENT_SECRET", "ATLAS_GITHUB_ALLOWED_USER"):
    os.environ.pop(var, None)

from starlette.testclient import TestClient

import atlas_mcp.app as appmod
from atlas_mcp.store import Project, new_project_body

client = TestClient(appmod.app)


def test_static_token_still_works_without_oauth():
    assert not appmod.OAUTH_ENABLED
    appmod.store.save(Project(id="fallback-project", meta={"name": "fallback-project"}, body=new_project_body("x")))

    resp = client.get("/api/projects", headers={"Authorization": "Bearer test-static-token"})
    assert resp.status_code == 200, resp.text
    ids = [p["id"] for p in resp.json()]
    assert "fallback-project" in ids, ids

    resp = client.get("/api/projects", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401, resp.status_code
    print("fallback mode (no OAuth): static token still works: OK")


with client:
    test_static_token_still_works_without_oauth()
