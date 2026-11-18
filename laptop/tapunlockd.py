#!/usr/bin/python3
import glob
import json
import logging
import os
import pwd
import signal
import socket
import struct
import sys

import dbus
import dbus.mainloop.glib
import dbus.service
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from gi.repository import GLib

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import tapunlock_protocol as proto  # noqa: E402

BLUEZ = "org.bluez"
LOGIN1 = "org.freedesktop.login1"
PROPS = "org.freedesktop.DBus.Properties"
ADV_PATH = "/xyz/bohesama/tapunlock/advertisement0"
SOCKET_PATH = os.environ.get("TAPUNLOCK_SOCKET", "/run/tap-unlock/pam.sock")
KEY_DIR = os.environ.get("TAPUNLOCK_KEY_DIR", "/etc/tap-unlock/keys")
TARGET_USER = os.environ["TAPUNLOCK_USER"]
WAIT_SECONDS = int(os.environ.get("TAPUNLOCK_WAIT", "20"))
ADV_INTERVAL_MS = 100

log = logging.getLogger("tap-unlockd")


def load_keys():
    keys = []
    for path in sorted(glob.glob(os.path.join(KEY_DIR, "*.pem"))):
        try:
            with open(path, "rb") as f:
                key = serialization.load_pem_public_key(f.read())
        except (OSError, ValueError) as e:
            log.warning("skip key %s: %s", path, e)
            continue
        if isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1":
            keys.append(key)
        else:
            log.warning("skip key %s: not an EC P-256 public key", path)
    return keys


class Advertisement(dbus.service.Object):
    def __init__(self, bus):
        super().__init__(bus, ADV_PATH)
        self.payload = b""

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, interface):
        data = dbus.Array([dbus.Byte(b) for b in self.payload], signature="y")
        return {
            "Type": "broadcast",
            "ManufacturerData": dbus.Dictionary({dbus.UInt16(proto.COMPANY_ID): data}, signature="qv"),
            "MinInterval": dbus.UInt32(ADV_INTERVAL_MS),
            "MaxInterval": dbus.UInt32(ADV_INTERVAL_MS),
        }

    @dbus.service.method("org.bluez.LEAdvertisement1")
    def Release(self):
        log.info("advertisement released by bluetoothd")


class Pending:
    def __init__(self, conn, service, pid):
        self.conn = conn
        self.fd = conn.fileno()
        self.service = service
        self.pid = pid
        self.timer = None
        self.watch = None


class Daemon:
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.target_uid = pwd.getpwnam(TARGET_USER).pw_uid
        self.adv = Advertisement(self.bus)
        self.book = None
        self.adapter_path = None
        self.tick_id = None
        self.adv_registered = False
        self.adv_busy = False
        self.locked_sessions = []
        self.pending = {}
        self.last_frame = b""

        self.bus.add_signal_receiver(self.on_login1_props, signal_name="PropertiesChanged",
                                     dbus_interface=PROPS, bus_name=LOGIN1, path_keyword="path")
        for name in ("SessionNew", "SessionRemoved"):
            self.bus.add_signal_receiver(self.refresh_locks, signal_name=name,
                                         dbus_interface="org.freedesktop.login1.Manager", bus_name=LOGIN1)
        self.bus.add_signal_receiver(self.on_interfaces_added, signal_name="InterfacesAdded",
                                     dbus_interface="org.freedesktop.DBus.ObjectManager", bus_name=BLUEZ)
        self.bus.add_signal_receiver(self.on_bluez_props, signal_name="PropertiesChanged",
                                     dbus_interface=PROPS, bus_name=BLUEZ, path_keyword="path")
        self.listen()
        self.refresh_locks()
        self.bus.watch_name_owner(BLUEZ, self.on_bluez_owner)

    def login1_manager(self):
        return dbus.Interface(self.bus.get_object(LOGIN1, "/org/freedesktop/login1"),
                              "org.freedesktop.login1.Manager")

    def refresh_locks(self, *_):
        locked = []
        for sid, uid, _user, _seat, path in self.login1_manager().ListSessions():
            if int(uid) != self.target_uid:
                continue
            props = dbus.Interface(self.bus.get_object(LOGIN1, path), PROPS)
            if bool(props.Get("org.freedesktop.login1.Session", "LockedHint")):
                locked.append(str(sid))
        if locked != self.locked_sessions:
            log.info("locked sessions: %s", ", ".join(locked) or "none")
        self.locked_sessions = locked
        self.update_arming()

    def on_login1_props(self, iface, changed, invalidated, path=None):
        if iface == "org.freedesktop.login1.Session" and ("LockedHint" in changed or "LockedHint" in invalidated):
            self.refresh_locks()

    def find_adapter(self):
        manager = dbus.Interface(self.bus.get_object(BLUEZ, "/"), "org.freedesktop.DBus.ObjectManager")
        for path, ifaces in manager.GetManagedObjects().items():
            adapter = ifaces.get("org.bluez.Adapter1")
            if adapter is not None and bool(adapter.get("Powered")) and "org.bluez.LEAdvertisingManager1" in ifaces:
                return str(path)
        return None

    def adapter(self, interface):
        return dbus.Interface(self.bus.get_object(BLUEZ, self.adapter_path), interface)

    def update_arming(self):
        wanted = bool(self.locked_sessions or self.pending)
        if wanted and self.book is None:
            self.arm()
        elif not wanted and self.book is not None:
            self.disarm()

    def arm(self):
        try:
            self.adapter_path = self.find_adapter()
        except dbus.DBusException as e:
            log.warning("bluetoothd unreachable: %s", e.get_dbus_message())
            self.adapter_path = None
        if self.adapter_path is None:
            log.warning("no powered Bluetooth adapter; cannot arm")
            return
        self.book = proto.ChallengeBook()
        self.last_frame = b""
        try:
            adapter = self.adapter("org.bluez.Adapter1")
            adapter.SetDiscoveryFilter({"Transport": "le", "DuplicateData": dbus.Boolean(True)})
            adapter.StartDiscovery()
        except dbus.DBusException as e:
            log.warning("start discovery: %s", e.get_dbus_message())
        self.tick_id = GLib.timeout_add_seconds(5, self.tick)
        self.sync_advert()
        log.info("armed on %s", self.adapter_path)

    def disarm(self, reason="idle"):
        self.book = None
        if self.tick_id is not None:
            GLib.source_remove(self.tick_id)
            self.tick_id = None
        if self.adapter_path is not None:
            try:
                self.adapter("org.bluez.Adapter1").StopDiscovery()
            except dbus.DBusException:
                pass
        self.sync_advert()
        log.info("disarmed (%s)", reason)

    def tick(self):
        if self.book is None:
            return False
        if self.book.due_for_rotation():
            self.book.rotate()
        self.sync_advert()
        return True

    def sync_advert(self):
        if self.adv_busy or self.adapter_path is None:
            return
        want = self.book is not None
        payload = proto.challenge_payload(self.book.nonce) if want else b""
        if self.adv_registered and (not want or payload != self.adv.payload):
            self.adv_busy = True
            self.adapter("org.bluez.LEAdvertisingManager1").UnregisterAdvertisement(
                ADV_PATH,
                reply_handler=lambda: self.adv_done(False),
                error_handler=lambda e: self.adv_done(False))
        elif not self.adv_registered and want:
            self.adv.payload = payload
            self.adv_busy = True
            self.adapter("org.bluez.LEAdvertisingManager1").RegisterAdvertisement(
                ADV_PATH, dbus.Dictionary({}, signature="sv"),
                reply_handler=lambda: self.adv_done(True),
                error_handler=self.adv_register_failed)

    def adv_done(self, registered):
        self.adv_registered = registered
        self.adv_busy = False
        self.sync_advert()

    def adv_register_failed(self, error):
        log.warning("register advertisement: %s", error.get_dbus_message())
        self.adv_registered = False
        self.adv_busy = False

    def on_bluez_owner(self, owner):
        self.adv_registered = False
        self.adv_busy = False
        if not owner:
            self.drop_radio("bluetoothd gone")
            return
        GLib.idle_add(lambda: self.update_arming() and False)

    def drop_radio(self, reason):
        for p in list(self.pending.values()):
            self.finish(p, "UNAVAILABLE", rearm=False)
        if self.book is not None:
            self.disarm(reason)

    def on_interfaces_added(self, path, ifaces):
        device = ifaces.get("org.bluez.Device1")
        if device is not None and "ManufacturerData" in device:
            self.on_manufacturer_data(device["ManufacturerData"])

    def on_bluez_props(self, iface, changed, invalidated, path=None):
        if iface == "org.bluez.Device1" and "ManufacturerData" in changed:
            self.on_manufacturer_data(changed["ManufacturerData"])
        elif iface == "org.bluez.Adapter1" and "Powered" in changed:
            if bool(changed["Powered"]):
                self.update_arming()
            else:
                self.drop_radio("adapter powered off")

    def on_manufacturer_data(self, manufacturer_data):
        if self.book is None:
            return
        value = manufacturer_data.get(proto.COMPANY_ID)
        if value is None:
            return
        data = bytes(value)
        if data == self.last_frame or not proto.is_response(data):
            return
        self.last_frame = data
        if not self.book.verify(data, load_keys()):
            log.info("response rejected: stale or reused nonce, or unknown key")
            return
        self.grant()
        if self.book is not None:
            self.sync_advert()

    def grant(self):
        if self.locked_sessions:
            manager = self.login1_manager()
            for sid in self.locked_sessions:
                manager.UnlockSession(sid, reply_handler=lambda: None,
                                      error_handler=lambda e, sid=sid: log.error("unlock session %s: %s", sid, e.get_dbus_message()))
            log.info("tap accepted: unlocking session(s) %s", ", ".join(self.locked_sessions))
        elif len(self.pending) == 1:
            p = next(iter(self.pending.values()))
            log.info("tap accepted: approving %s request (pid %d)", p.service, p.pid)
            self.finish(p, "OK")
        elif self.pending:
            log.warning("tap accepted but %d requests are waiting; refusing all", len(self.pending))
            for p in list(self.pending.values()):
                self.finish(p, "AMBIGUOUS")
        else:
            log.info("tap accepted with nothing to approve")

    def listen(self):
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.server.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o600)
        self.server.listen(8)
        GLib.io_add_watch(self.server.fileno(), GLib.IO_IN, self.on_accept)

    def on_accept(self, fd, condition):
        conn, _ = self.server.accept()
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", creds)
        if uid != 0:
            log.warning("rejected socket peer pid=%d uid=%d", pid, uid)
            conn.close()
            return True
        conn.settimeout(1.0)
        try:
            request = json.loads(conn.recv(4096).decode())
            user, service = str(request["user"]), str(request["service"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            log.warning("bad request from pid %d: %s", pid, e)
            conn.close()
            return True
        if user != TARGET_USER or self.locked_sessions:
            self.send(conn, "SKIP")
            conn.close()
            return True
        p = Pending(conn, service, pid)
        self.pending[p.fd] = p
        self.update_arming()
        if self.book is None:
            self.finish(p, "UNAVAILABLE")
            return True
        self.send(conn, f"WAIT {WAIT_SECONDS}")
        conn.setblocking(False)
        p.timer = GLib.timeout_add_seconds(WAIT_SECONDS, self.on_timeout, p)
        p.watch = GLib.io_add_watch(p.fd, GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self.on_hangup, p)
        log.info("%s request waiting (pid %d)", service, pid)
        return True

    def on_timeout(self, p):
        p.timer = None
        log.info("%s request timed out (pid %d)", p.service, p.pid)
        self.finish(p, "TIMEOUT")
        return False

    def on_hangup(self, fd, condition, p):
        p.watch = None
        log.info("%s request abandoned (pid %d)", p.service, p.pid)
        self.finish(p, None)
        return False

    @staticmethod
    def send(conn, line):
        try:
            conn.sendall((line + "\n").encode())
        except OSError:
            pass

    def finish(self, p, verdict, rearm=True):
        if self.pending.pop(p.fd, None) is None:
            return
        for source in (p.timer, p.watch):
            if source is not None:
                GLib.source_remove(source)
        p.timer = p.watch = None
        if verdict is not None:
            self.send(p.conn, verdict)
        p.conn.close()
        if rearm:
            self.update_arming()

    def shutdown(self):
        for p in list(self.pending.values()):
            self.finish(p, "UNAVAILABLE", rearm=False)
        if self.adapter_path is not None:
            try:
                if self.book is not None:
                    self.adapter("org.bluez.Adapter1").StopDiscovery()
                if self.adv_registered:
                    self.adapter("org.bluez.LEAdvertisingManager1").UnregisterAdvertisement(ADV_PATH)
            except dbus.DBusException:
                pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    daemon = Daemon()
    loop = GLib.MainLoop()

    def stop():
        daemon.shutdown()
        loop.quit()
        return False

    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, stop)
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, stop)
    loop.run()


if __name__ == "__main__":
    main()
