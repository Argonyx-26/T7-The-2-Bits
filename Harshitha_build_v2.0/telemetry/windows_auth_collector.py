import json
import time
import urllib.request
import xml.etree.ElementTree as ET

import win32evtlog


CHANNEL = "Security"
BACKEND_URL = "http://127.0.0.1:8000/events"

EVENT_NAMES = {
    4624: "logon_success",
    4625: "logon_failure",
    4648: "explicit_credentials",
    4634: "logoff",
    4647: "user_initiated_logoff",
}

QUERY = (
    "*[System["
    "EventID=4624 or "
    "EventID=4625 or "
    "EventID=4648 or "
    "EventID=4634 or "
    "EventID=4647"
    "]]"
)

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def parse_event(xml_text):
    root = ET.fromstring(xml_text)

    system = root.find("e:System", NS)
    event_data = root.find("e:EventData", NS)

    if system is None:
        raise ValueError("Missing System section")

    event_id_node = system.find("e:EventID", NS)
    computer_node = system.find("e:Computer", NS)
    time_node = system.find("e:TimeCreated", NS)
    record_node = system.find("e:EventRecordID", NS)

    event_id = int(event_id_node.text)

    timestamp = None
    if time_node is not None:
        timestamp = time_node.attrib.get("SystemTime")

    computer = ""
    if computer_node is not None:
        computer = computer_node.text or ""

    record_id = None
    if record_node is not None and record_node.text:
        record_id = int(record_node.text)

    fields = {}

    if event_data is not None:
        for node in event_data.findall("e:Data", NS):
            name = node.attrib.get("Name")
            value = node.text or ""

            if name:
                fields[name] = value

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "record_id": record_id,
        "fields": fields,
    }


def normalize_event(parsed):
    fields = parsed["fields"]
    event_id = parsed["event_id"]

    logon_type = fields.get("LogonType")

    logon_type_names = {
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RemoteInteractive",
        "11": "CachedInteractive",
    }

    target_user = fields.get("TargetUserName")
    subject_user = fields.get("SubjectUserName")

    user = target_user or subject_user

    source_ip = fields.get("IpAddress")
    source_port = fields.get("IpPort")

    return {
        "id": f"windows-security-{parsed['record_id']}",
        "timestamp": parsed["timestamp"],
        "source": "windows_security",
        "event_type": "authentication",
        "event_name": EVENT_NAMES.get(
            event_id,
            f"windows_event_{event_id}"
        ),
        "event_id": event_id,

        "user": {
            "name": user,
            "target_name": target_user,
            "target_sid": fields.get("TargetUserSid"),
            "target_domain": fields.get("TargetDomainName"),
            "subject_name": subject_user,
            "subject_sid": fields.get("SubjectUserSid"),
            "subject_domain": fields.get("SubjectDomainName"),
        },

        "host": {
            "name": parsed["computer"]
            or fields.get("WorkstationName"),
            "workstation": fields.get("WorkstationName"),
        },

        "authentication": {
            "logon_type": (
                int(logon_type)
                if logon_type and logon_type.isdigit()
                else None
            ),
            "logon_type_name": logon_type_names.get(
                logon_type
            ),
            "logon_process": fields.get(
                "LogonProcessName"
            ),
            "package": fields.get(
                "AuthenticationPackageName"
            ),
        },

        "network": {
            "source_ip": source_ip,
            "source_port": (
                int(source_port)
                if source_port and source_port.isdigit()
                else None
            ),
        },

        "process": {
            "name": fields.get("ProcessName"),
            "pid": fields.get("ProcessId"),
        },

        "correlation": {
            "logon_id": fields.get("TargetLogonId"),
            "linked_logon_id": fields.get(
                "TargetLinkedLogonId"
            ),
        },

        "raw": fields,
    }


def send_to_backend(event):
    payload = json.dumps(event).encode("utf-8")

    request = urllib.request.Request(
        BACKEND_URL,
        data=payload,
        headers={
            "Content-Type": "application/json"
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=2,
        ) as response:

            response_body = response.read().decode("utf-8")

            print(
                f"[SENTRA -> BACKEND] "
                f"HTTP {response.status} "
                f"{response_body}"
            )

    except Exception as exc:
        print(
            "[SENTRA -> BACKEND ERROR] "
            f"{type(exc).__name__}: {exc}"
        )


def handle_event(action, context, event_handle):

    if action != win32evtlog.EvtSubscribeActionDeliver:
        return

    try:
        xml_text = win32evtlog.EvtRender(
            event_handle,
            win32evtlog.EvtRenderEventXml,
        )

        parsed = parse_event(xml_text)

        normalized = normalize_event(parsed)

        print("\n" + "=" * 80)

        print(
            f"[SENTRA] "
            f"{normalized['event_name']} "
            f"(Event ID {normalized['event_id']})"
        )

        print(
            f"Time       : "
            f"{normalized['timestamp']}"
        )

        print(
            f"User       : "
            f"{normalized['user']['name']}"
        )

        print(
            f"Host       : "
            f"{normalized['host']['name']}"
        )

        if normalized["authentication"]["logon_type"]:
            print(
                f"Logon Type : "
                f"{normalized['authentication']['logon_type']} "
                f"("
                f"{normalized['authentication']['logon_type_name']}"
                f")"
            )

        print(
            f"Source IP  : "
            f"{normalized['network']['source_ip']}"
        )

        print(
            f"Process    : "
            f"{normalized['process']['name']}"
        )

        print("\nNormalized SENTRA Event:")

        print(
            json.dumps(
                normalized,
                indent=2
            )
        )

        print("=" * 80)

        # Send normalized event to FastAPI
        send_to_backend(normalized)

    except Exception as exc:

        print("\n[SENTRA COLLECTOR ERROR]")
        print(type(exc).__name__, exc)


def main():

    print("=" * 80)
    print("SENTRA — Windows Authentication Collector")
    print("=" * 80)

    print(f"Channel : {CHANNEL}")
    print(
        "Backend : "
        f"{BACKEND_URL}"
    )

    print(
        "Watching : "
        + ", ".join(
            f"{event_id} ({name})"
            for event_id, name in EVENT_NAMES.items()
        )
    )

    print()
    print("LIVE: waiting for NEW Windows Security events...")
    print("Press Ctrl+C to stop.")
    print()

    subscription = win32evtlog.EvtSubscribe(
        CHANNEL,
        win32evtlog.EvtSubscribeToFutureEvents,
        Callback=handle_event,
        Query=QUERY,
    )

    print("[OK] Security Event Log subscription established.")
    print("[OK] SENTRA collector is LIVE.")
    print()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping SENTRA collector...")


if __name__ == "__main__":
    main()