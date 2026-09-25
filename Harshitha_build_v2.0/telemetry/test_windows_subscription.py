import win32evtlog

CHANNEL = "Application"

QUERY = (
    "*[System["
    "EventID=100"
    "]]"
)


def callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml = win32evtlog.EvtRender(
                event_handle,
                win32evtlog.EvtRenderEventXml,
            )

            print("\n=== LIVE EVENT RECEIVED ===")
            print(xml)

        except Exception as exc:
            print("\n[ERROR RENDERING EVENT]")
            print(type(exc).__name__, exc)

    elif action == win32evtlog.EvtSubscribeActionError:
        print("\n[SUBSCRIPTION ERROR]")
        print(event_handle)


subscription = win32evtlog.EvtSubscribe(
    CHANNEL,
    win32evtlog.EvtSubscribeToFutureEvents,
    Callback=callback,
    Query=QUERY,
)

print("========================================")
print("SENTRA EVENT SUBSCRIPTION TEST")
print("========================================")
print("Channel : Application")
print("Event   : 100")
print()
print("LIVE: waiting for a NEW event...")
print("Run eventcreate in another Administrator PowerShell.")
print("Press Ctrl+C to stop.\n")

try:
    while True:
        # Keep the process alive.
        import time
        time.sleep(1)

except KeyboardInterrupt:
    print("\nStopping listener...")