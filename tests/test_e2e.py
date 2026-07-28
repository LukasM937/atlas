import json, urllib.request
import os
BASE=os.environ.get("ATLAS_BASE","http://127.0.0.1:8787"); TOK=os.environ.get("ATLAS_TOKEN","testtoken123"); MCP=f"{BASE}/mcp/{TOK}/"
def rpc(method, params=None, _id=1):
    body=json.dumps({"jsonrpc":"2.0","id":_id,"method":method,"params":params or {}}).encode()
    req=urllib.request.Request(MCP, data=body, headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"})
    with urllib.request.urlopen(req) as r: return json.loads(r.read())
def notify(method, params=None):
    body=json.dumps({"jsonrpc":"2.0","method":method,"params":params or {}}).encode()
    req=urllib.request.Request(MCP, data=body, headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream"})
    try: urllib.request.urlopen(req)
    except Exception as e: pass

init=rpc("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}})
print("server:", init["result"]["serverInfo"], "\ninstructions len:", len(init["result"].get("instructions","")))
notify("notifications/initialized")
tools=rpc("tools/list")["result"]["tools"]
print("tools:", [t["name"] for t in tools])
def call(n,a):
    r=rpc("tools/call",{"name":n,"arguments":a})
    if "error" in r: return "ERR "+json.dumps(r["error"])[:300]
    return r["result"]["content"][0]["text"]

print("\n--", call("atlas_upsert_project",{"params":{"id":"demo-widget","name":"demo-widget","category":"software","status":"active","priority":"S","completion":45,"tags":["demo","fixture"],"section":"Summary","content":"Fictional e2e test fixture: a widget that does not exist, used to exercise the protocol round trip."}}))
print("--", call("atlas_upsert_project",{"params":{"id":"demo-gadget","name":"demo-gadget","category":"hardware","status":"advanced","priority":"B","completion":70,"tags":["demo","fixture"],"section":"Summary","content":"Second fictional fixture, used to exercise list/filter across more than one project."}}))
print("--", call("atlas_append_entry",{"params":{"id":"demo-widget","kind":"decision","text":"Use a temp store dir per test run, because a shared dir leaks state across runs.","author":"claude"}}))
print("--", call("atlas_append_entry",{"params":{"id":"demo-widget","kind":"result","text":"All protocol round trips pass locally; CI coverage still open.","author":"claude"}}))
print("\n== list ==\n"+call("atlas_list_projects",{"params":{"status":"active"}}))
print("\n== search ==\n"+call("atlas_search",{"params":{"query":"protocol round trip"}}))
print("\n== get ==\n"+call("atlas_get_project",{"params":{"id":"demo-widget","log_limit":5}}))
print("\n== overview ==\n"+call("atlas_overview",{}))
print("\n== errors ==")
print(call("atlas_get_project",{"params":{"id":"nonexistent-fixture"}})[:200])
print(call("atlas_upsert_project",{"params":{"id":"x","section":"Bogus","content":"y"}})[:200])
res=rpc("resources/list")["result"]["resources"]; print("\nresources:", [r["uri"] for r in res])
print("prompts:", [p["name"] for p in rpc("prompts/list")["result"]["prompts"]])
r=rpc("resources/read",{"uri":"atlas://index"})["result"]["contents"][0]["text"]; print("\natlas://index ->\n"+r)
