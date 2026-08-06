import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from atlas_mcp.tenants import TenantRegistry, InviteRegistry, get_store_for
from atlas_mcp.store import Project, new_project_body


def test_tenant_registry():
    d = tempfile.mkdtemp()
    reg = TenantRegistry(os.path.join(d, "tenants.json"))
    assert not reg.is_allowed("alice")
    reg.add("alice")
    assert reg.is_allowed("alice")
    assert not reg.is_allowed("bob")
    assert reg.list() == ["alice"]
    print("tenant registry: OK")


def test_invite_registry():
    d = tempfile.mkdtemp()
    reg = InviteRegistry(os.path.join(d, "invites.json"))
    token = reg.create()
    assert reg.redeem(token) is True
    assert reg.redeem(token) is False, "an invite must not be redeemable twice"

    expired = reg.create(ttl_seconds=-1)
    assert reg.redeem(expired) is False, "an expired invite must not redeem"
    print("invite registry: OK")


def test_invite_registry_cross_process():
    # Simulates the real deployment shape: `python -m atlas_mcp.invite` mints
    # in one process, the running server redeems in another. Two separate
    # InviteRegistry objects pointed at the same file, standing in for that.
    d = tempfile.mkdtemp()
    path = os.path.join(d, "invites.json")
    minter = InviteRegistry(path)
    server = InviteRegistry(path)

    token = minter.create()
    assert server.is_valid(token), "the 'server' instance must see an invite minted by another instance"
    assert server.redeem(token) is True
    assert minter.is_valid(token) is False, "redeeming via one instance must be visible to the other"
    print("invite registry cross-process: OK")


def test_isolation():
    d = tempfile.mkdtemp()
    alice = get_store_for("alice", d)
    bob = get_store_for("bob", d)
    assert alice.root != bob.root

    alice.save(Project(id="secret-project", meta={"name": "secret-project"}, body=new_project_body("alice's plan")))
    assert alice.exists("secret-project")
    assert not bob.exists("secret-project"), "bob's store must not see alice's project"
    try:
        bob.load("secret-project")
        raise SystemExit("bob loaded alice's project -- cross-tenant leak")
    except Exception as e:
        assert "No project" in str(e)
    assert bob.all() == []
    assert bob.search("alice") == []
    print("tenant isolation: OK")


test_tenant_registry()
test_invite_registry()
test_invite_registry_cross_process()
test_isolation()
