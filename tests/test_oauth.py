"""OAuth provider hardening: consent before code issue, GitHub-id-bound
tenancy, token lifecycle (expiry, grant-wide revocation, replay detection,
deauthorization), and anonymous-ingress caps. No network: GitHub is stubbed."""
import asyncio, os, stat, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.shared.auth import OAuthClientInformationFull

from atlas_mcp import github_oauth as go
from atlas_mcp.tenants import TenantRegistry

GITHUB = {"login": "alice", "id": 1}


async def _fake_verify(code, cid, secret, cb):
    return GITHUB["login"], GITHUB["id"]


go.verify_github_code = _fake_verify


def make(tmp=None):
    d = tmp or tempfile.mkdtemp()
    reg = TenantRegistry(os.path.join(d, "tenants.json"))
    reg.add("alice", 1)
    prov = go.GitHubOAuthProvider(os.path.join(d, "oauth_state.json"), "cid", "sec", reg, "https://x/cb")
    return prov, reg, d


def client(n=0, name="Evil App", redirect="https://attacker.example/cb"):
    return OAuthClientInformationFull(
        client_id=f"c{n}", client_name=name, redirect_uris=[redirect], client_id_issued_at=n,
        token_endpoint_auth_method="none")


def params(c, state="s"):
    return AuthorizationParams(state=state, scopes=["mcp"], code_challenge="x" * 43,
                               redirect_uri=c.redirect_uris[0], redirect_uri_provided_explicitly=True)


async def full_grant(prov, c):
    url = await prov.authorize(c, params(c))
    gh_state = url.split("state=")[1].split("&")[0]
    pending = await prov.stage_github_login("code", gh_state)
    redirect = await prov.complete_login_consent(gh_state, pending["consent_nonce"])
    code = redirect.split("code=")[1].split("&")[0]
    ac = await prov.load_authorization_code(c, code)
    return await prov.exchange_authorization_code(c, ac)


async def t_consent_and_binding():
    prov, reg, _ = make()
    c = client(); await prov.register_client(c)
    url = await prov.authorize(c, params(c))
    gh_state = url.split("state=")[1].split("&")[0]
    pending = await prov.stage_github_login("code", gh_state)
    assert not prov._auth_codes, "no authorization code may exist before the user approves the client"
    assert pending["client_name"] == "Evil App" and pending["subject"] == "alice"
    try:
        await prov.complete_login_consent(gh_state, "guess"); raise SystemExit("wrong nonce accepted")
    except AuthorizeError:
        pass
    assert not prov._auth_codes
    # approving without having completed the GitHub login is impossible
    url = await prov.authorize(c, params(c)); s2 = url.split("state=")[1].split("&")[0]
    try:
        await prov.complete_login_consent(s2, ""); raise SystemExit("consent without login accepted")
    except AuthorizeError:
        pass
    # a recycled GitHub username (same login, different id) is not the tenant
    GITHUB["id"] = 999
    url = await prov.authorize(c, params(c)); s3 = url.split("state=")[1].split("&")[0]
    try:
        await prov.stage_github_login("code", s3); raise SystemExit("recycled username accepted")
    except AuthorizeError:
        pass
    GITHUB["id"] = 1
    print("consent required + tenancy bound to GitHub id: OK")


async def t_token_lifecycle():
    prov, reg, _ = make()
    c = client(); await prov.register_client(c)
    tok = await full_grant(prov, c)
    rt = prov._refresh_tokens[tok.refresh_token]
    assert rt.expires_at and rt.expires_at <= time.time() + go.REFRESH_TOKEN_TTL + 5, "refresh token must expire"
    # expiry
    rt.expires_at = int(time.time()) - 1
    assert await prov.load_refresh_token(c, tok.refresh_token) is None
    assert tok.refresh_token not in prov._refresh_tokens, "expired token is dropped"
    tok = await full_grant(prov, c)

    # rotation, then replay of the old refresh token revokes the whole family
    t2 = await prov.exchange_refresh_token(c, await prov.load_refresh_token(c, tok.refresh_token), [])
    assert await prov.load_access_token(t2.access_token)
    assert await prov.load_refresh_token(c, tok.refresh_token) is None  # replay...
    assert await prov.load_access_token(t2.access_token) is None, "replay must revoke successors"
    assert await prov.load_refresh_token(c, t2.refresh_token) is None

    # revoking the ACCESS token kills the sibling refresh token and descendants
    tok = await full_grant(prov, c)
    t2 = await prov.exchange_refresh_token(c, await prov.load_refresh_token(c, tok.refresh_token), [])
    await prov.revoke_token(await prov.load_access_token(t2.access_token))
    assert await prov.load_refresh_token(c, t2.refresh_token) is None
    assert await prov.load_access_token(t2.access_token) is None
    # ...and revoking a REFRESH token kills its access token
    tok = await full_grant(prov, c)
    await prov.revoke_token(await prov.load_refresh_token(c, tok.refresh_token))
    assert await prov.load_access_token(tok.access_token) is None
    print("refresh expiry, rotation replay, grant-wide revocation: OK")


async def t_deauthorization():
    prov, reg, d = make()
    c = client(); await prov.register_client(c)
    tok = await full_grant(prov, c)
    import json
    p = reg.state_path; data = json.loads(p.read_text()); del data["alice"]; p.write_text(json.dumps(data))
    assert await prov.load_access_token(tok.access_token) is None, "removed tenant's access token must die at once"
    try:
        await prov.exchange_refresh_token(c, await prov.load_refresh_token(c, tok.refresh_token), [])
        raise SystemExit("removed tenant rotated its refresh token")
    except TokenError:
        pass
    assert not prov._refresh_tokens and not prov._access_tokens
    print("tenant removal propagates to live tokens: OK")


async def t_ingress_caps():
    prov, reg, d = make()
    big = client(1); big.client_name = "x" * (go.MAX_CLIENT_METADATA_BYTES + 1)
    try:
        await prov.register_client(big); raise SystemExit("oversized registration accepted")
    except RegistrationError:
        pass
    old = go.MAX_CLIENTS; go.MAX_CLIENTS = 3
    try:
        for i in range(3): await prov.register_client(client(i))
        await prov.register_client(client(10))          # evicts the oldest idle client
        assert len(prov._clients) == 3 and "c0" not in prov._clients
        used = client(20); prov._clients = {}
        for i in range(3):
            prov._clients[f"c{i}"] = client(i)
        for i in range(3):                               # every client holds a live token
            await full_grant(prov, prov._clients[f"c{i}"])
        try:
            await prov.register_client(client(11)); raise SystemExit("registry exceeded its cap")
        except RegistrationError:
            pass
    finally:
        go.MAX_CLIENTS = old
    c = client(30)
    for field in ("state",):
        bad = AuthorizationParams(state="s" * (go.PENDING_FIELD_MAX_CHARS + 1), scopes=["mcp"],
                                  code_challenge="x" * 43, redirect_uri=c.redirect_uris[0],
                                  redirect_uri_provided_explicitly=True)
        try:
            await prov.authorize(c, bad); raise SystemExit("oversized authorize field accepted")
        except AuthorizeError:
            pass
    old = go.PENDING_MAX_ENTRIES; go.PENDING_MAX_ENTRIES = 5
    try:
        for _ in range(5): await prov.authorize(c, params(c))
        try:
            await prov.authorize(c, params(c)); raise SystemExit("pending cap not enforced")
        except AuthorizeError:
            pass
        for v in prov._pending.values(): v["expires_at"] = 0     # expired entries are pruned, not counted
        await prov.authorize(c, params(c))
    finally:
        go.PENDING_MAX_ENTRIES = old
    print("registration + pending-state caps: OK")


async def t_state_file_private():
    os.umask(0o022)
    prov, reg, d = make()
    await prov.register_client(client())
    mode = stat.S_IMODE(os.stat(prov.state_path).st_mode)
    assert mode == 0o600, oct(mode)
    print("oauth_state.json is owner-only: OK")


for t in (t_consent_and_binding, t_token_lifecycle, t_deauthorization, t_ingress_caps, t_state_file_private):
    asyncio.run(t())
