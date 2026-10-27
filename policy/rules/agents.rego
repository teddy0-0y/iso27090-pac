# AI agent privileges and oversight — ISO/IEC 27090 5.3, 6.11.3.2, 6.11.3.3
# Only evaluated when spec.agent.enabled == true.
package ai27090.rules.agents

import data.ai27090.lib

agent := lib.get(["spec", "agent"], {})

active if object.get(agent, "enabled", false) == true

creds := object.get(agent, "credentials", {})

tools := object.get(agent, "tools", [])

max_ttl_minutes := 60

high_impact_actions := {"external", "delete", "execute", "payment"}

# AIS-AGT-01: the agent authenticates as itself, not by inheriting the user's permissions
findings contains lib.finding("AIS-AGT-01", "6.11.3.3", "deny", sprintf("Agent identity is '%v'; it must use a dedicated identity, not inherit user permissions", [id])) if {
	active
	id := object.get(creds, "identity", "unspecified")
	id != "dedicated"
}

# AIS-AGT-02: credentials are short-lived and expire after the task
findings contains lib.finding("AIS-AGT-02", "5.3, 6.11.3.3", "deny", sprintf("Agent credentials must expire within %d minutes (just-in-time access)", [max_ttl_minutes])) if {
	active
	not object.get(creds, "ttl_minutes", 0) > 0
}

findings contains lib.finding("AIS-AGT-02", "5.3, 6.11.3.3", "deny", sprintf("Agent credential TTL is %v minutes; must be <= %d", [ttl, max_ttl_minutes])) if {
	active
	ttl := object.get(creds, "ttl_minutes", 0)
	ttl > max_ttl_minutes
}

# AIS-AGT-03: tool permissions are task-specific (no wildcard scopes)
findings contains lib.finding("AIS-AGT-03", "6.11.3.3", "deny", sprintf("Tool '%v' has a wildcard scope; permissions must be task-specific", [object.get(t, "name", "?")])) if {
	active
	some t in tools
	some s in object.get(t, "scopes", [])
	contains(s, "*")
}

findings contains lib.finding("AIS-AGT-03", "6.11.3.3", "deny", sprintf("Tool '%v' declares no scopes", [object.get(t, "name", "?")])) if {
	active
	some t in tools
	count(object.get(t, "scopes", [])) == 0
}

# AIS-AGT-04: high-impact actions need explicit human confirmation
findings contains lib.finding("AIS-AGT-04", "6.11.3.2, 6.11.3.3", "deny", sprintf("Tool '%v' performs '%v' actions without human approval", [object.get(t, "name", "?"), t.action])) if {
	active
	some t in tools
	t.action in high_impact_actions
	not object.get(t, "requires_human_approval", false) == true
}

findings contains lib.finding("AIS-AGT-04", "6.11.3.2", "warn", sprintf("Tool '%v' writes data without human approval; confirm this is intended", [object.get(t, "name", "?")])) if {
	active
	some t in tools
	t.action == "write"
	not object.get(t, "requires_human_approval", false) == true
}

# AIS-AGT-05: agents that execute code or drive a computer run in a restricted sandbox
findings contains lib.finding("AIS-AGT-05", "6.11.3.3", "deny", "Agent can execute code or use a computer but is not confined to a sandboxed environment") if {
	active
	executes
	object.get(agent, "execution_environment", "") != "sandboxed"
}

executes if object.get(agent, "computer_use", false) == true

executes if {
	some t in tools
	t.action == "execute"
}

# AIS-AGT-06: every agent action is written to an audit trail
findings contains lib.finding("AIS-AGT-06", "6.11.3.3, 7.5", "deny", "Agent actions are not recorded in an audit log") if {
	active
	not object.get(agent, "action_audit_log", false) == true
}

# AIS-AGT-07: anomalous agent behaviour can restrict privileges (kill switch)
findings contains lib.finding("AIS-AGT-07", "6.11.3.3", "warn_high", "No mechanism to restrict or halt the agent when anomalous behaviour is detected") if {
	active
	not object.get(agent, "kill_switch", false) == true
}
