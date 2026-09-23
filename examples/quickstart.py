from pathlib import Path

from pqc_a2a import AgentIdentity, ReplayCache, open_envelope, seal

PASSWORD = "change-this-development-password"
STATE = Path("agent-a.identity.json")

if STATE.exists():
    sender = AgentIdentity.load(STATE, PASSWORD)
else:
    sender = AgentIdentity("agent-a")
    sender.save(STATE, PASSWORD)

recipient = AgentIdentity("agent-b")
envelope = seal(sender, recipient, {"type": "task.result", "value": 42})
message = open_envelope(recipient, sender, envelope, ReplayCache())
print(message)
