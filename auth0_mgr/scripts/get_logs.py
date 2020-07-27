import auth0_mgr
import auth0_mgr.tokens
import json
import os
mgr = auth0_mgr.tokens.AdminTokenMgr()

query = 'type:fec* OR type:sec*'

params = {
    "page": 0,
    "per_page": 100,
    "sort": "date:-1",
    "q": query,
}

_file = "logs.json"

try:
    os.remove(_file)
except Exception:
    pass

log_entries = list()
for i in range(0, 10):
    params["page"] = i
    data = mgr.auth0.logs.search(**params)
    log_entries.extend(data['logs'])

with open(_file, 'w') as f:
    f.write(json.dumps(log_entries))




# 'Failed Exchange'
#'Success Exchange'