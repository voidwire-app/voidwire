#!/usr/bin/env python3
"""Minimal org.kde.StatusNotifierWatcher for the Linux smoke test (CI only).

Owns the watcher name on the session bus and prints one line per tray item
that registers, so the test can see that the app's tray icon came up.
"""
import asyncio

from dbus_next import PropertyAccess
from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, dbus_property, method, signal


class Watcher(ServiceInterface):
    def __init__(self):
        super().__init__("org.kde.StatusNotifierWatcher")
        self.items = []

    @method()
    def RegisterStatusNotifierItem(self, service: "s"):
        print("REGISTERED_ITEM", flush=True)
        self.items.append(service)
        self.StatusNotifierItemRegistered(service)

    @method()
    def RegisterStatusNotifierHost(self, service: "s"):
        pass

    @signal()
    def StatusNotifierItemRegistered(self, service) -> "s":
        return service

    @dbus_property(access=PropertyAccess.READ)
    def RegisteredStatusNotifierItems(self) -> "as":
        return self.items

    @dbus_property(access=PropertyAccess.READ)
    def IsStatusNotifierHostRegistered(self) -> "b":
        return True

    @dbus_property(access=PropertyAccess.READ)
    def ProtocolVersion(self) -> "i":
        return 0


async def main():
    bus = await MessageBus().connect()
    bus.export("/StatusNotifierWatcher", Watcher())
    await bus.request_name("org.kde.StatusNotifierWatcher")
    print("WATCHER_UP", flush=True)
    await asyncio.get_running_loop().create_future()


asyncio.run(main())
