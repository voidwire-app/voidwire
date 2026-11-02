#!/usr/bin/env python3
"""A stand-in xdg-desktop-portal GlobalShortcuts (tests only, M5.1 L3).

Owns org.freedesktop.portal.Desktop on the current session bus and answers
CreateSession / BindShortcuts as a desktop would after the user confirms.
Test hooks on org.voidwire.PortalStub at /stub:
  Press()  -> emits Activated for the bound shortcut (activation_token "stub-token")
  Closed() -> b: whether the client closed its session
Run under dbus-run-session; needs python3-dbus-next.
"""
import asyncio

from dbus_next import Message, MessageType, Variant
from dbus_next.aio import MessageBus

PATH = "/org/freedesktop/portal/desktop"
IFACE = "org.freedesktop.portal.GlobalShortcuts"
state = {"session": None, "client": None, "closed": False, "seq": 0}


def reply(bus, msg, sig="", body=()):
    bus.send(Message.new_method_return(msg, sig, list(body)))


def response(bus, client, token, results):
    sender = client.lstrip(":").replace(".", "_")
    bus.send(Message.new_signal(f"{PATH}/request/{sender}/{token}",
                                "org.freedesktop.portal.Request", "Response",
                                "ua{sv}", [0, results]))


def handler(bus):
    def on(msg):
        if msg.message_type != MessageType.METHOD_CALL:
            return False
        m, i = msg.member, msg.interface
        if i == "org.freedesktop.DBus.Properties" and m == "Get" and msg.path == PATH:
            if msg.body == [IFACE, "version"]:
                reply(bus, msg, "v", [Variant("u", 1)])
            else:
                bus.send(Message.new_error(msg, "org.freedesktop.DBus.Error.UnknownProperty", "no"))
            return True
        if i == IFACE and m == "CreateSession":
            opts = msg.body[0]
            tok, stok = opts["handle_token"].value, opts["session_handle_token"].value
            sender = msg.sender.lstrip(":").replace(".", "_")
            state.update(session=f"{PATH}/session/{sender}/{stok}", client=msg.sender, closed=False)
            reply(bus, msg, "o", [f"{PATH}/request/{sender}/{tok}"])
            response(bus, msg.sender, tok, {"session_handle": Variant("s", state["session"])})
            return True
        if i == IFACE and m == "BindShortcuts":
            session, shortcuts, _parent, opts = msg.body
            tok = opts["handle_token"].value
            sender = msg.sender.lstrip(":").replace(".", "_")
            reply(bus, msg, "o", [f"{PATH}/request/{sender}/{tok}"])
            bound = []
            for sid, props in shortcuts:
                pref = props.get("preferred_trigger")
                desc = "Ctrl+Shift+V (stub)" if pref and pref.value == "CTRL+SHIFT+v" else "unset"
                bound.append([sid, {"description": props["description"],
                                    "trigger_description": Variant("s", desc)}])
            response(bus, msg.sender, tok, {"shortcuts": Variant("a(sa{sv})", bound)})
            return True
        if i == "org.freedesktop.portal.Session" and m == "Close":
            if msg.path == state["session"]:
                state["closed"] = True
            reply(bus, msg)
            return True
        if i == "org.voidwire.PortalStub" and m == "Press":
            bus.send(Message.new_signal(PATH, IFACE, "Activated", "osta{sv}",
                                        [state["session"], "send-clipboard", 1,
                                         {"activation_token": Variant("s", "stub-token")}]))
            reply(bus, msg)
            return True
        if i == "org.voidwire.PortalStub" and m == "Closed":
            reply(bus, msg, "b", [state["closed"]])
            return True
        return False
    return on


async def main():
    bus = await MessageBus().connect()
    bus.add_message_handler(handler(bus))
    await bus.request_name("org.freedesktop.portal.Desktop")
    await bus.request_name("org.voidwire.PortalStub")
    print("portal-stub: ready", flush=True)
    await asyncio.Future()


asyncio.run(main())
