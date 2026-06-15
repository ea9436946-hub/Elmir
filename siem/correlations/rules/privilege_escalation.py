class PrivilegeEscalationRule:
    name = "privilege_escalation"

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.severity = config.get("severity", "CRITICAL")

    def evaluate(self, event: dict, store) -> dict | None:
        etype = event.get("event_type")

        # sudo failure followed quickly by success is suspicious, but here we
        # flag direct su to root and sudo -i patterns
        if etype == "su_session":
            username = event.get("username", "")
            message = event.get("message", "")
            if "root" in message:
                return {
                    "rule_name": self.name,
                    "severity": self.severity,
                    "source_ip": event.get("source_ip"),
                    "username": event.get("username"),
                    "description": f"Privilege escalation to root via su by {username}",
                    "event_ids": [event.get("id")] if event.get("id") else [],
                }

        if etype == "sudo_command":
            message = event.get("message", "")
            # Flag dangerous sudo commands
            dangerous = ("/bin/bash", "/bin/sh", "su -", "passwd root", "visudo", "chmod 777")
            for cmd in dangerous:
                if cmd in message:
                    return {
                        "rule_name": self.name,
                        "severity": self.severity,
                        "source_ip": event.get("source_ip"),
                        "username": event.get("username"),
                        "description": f"Suspicious sudo command: {message}",
                        "event_ids": [event.get("id")] if event.get("id") else [],
                    }

        return None
