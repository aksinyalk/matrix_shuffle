import asyncio
import json
import sys
from io import StringIO

from shuffle_sdk import AppBase
from nio import JoinResponse
import nio

import matrix_client
from matrix_client import (
    normalize_homeserver,
    normalize_room_id,
    load_session,
    save_session,
    whoami_ok,
    login_password,
    build_nio_client,
    cross_sign_device,
)


class MatrixCrypto(AppBase):
    __version__ = "1.0.0"
    app_name = "Matrix Crypto"  # должно совпадать с "name" в api.yaml

    def __init__(self, redis, logger, console_logger=None):
        super().__init__(redis, logger, console_logger)

    def send_encrypted_message(self, homeserver, room, message, username, password, recovery_key):
        session_file = "/app/nio_store/matrix_session.json"

        async def _run():
            hs = normalize_homeserver(homeserver)
            room_id = normalize_room_id(room)

            session = load_session(session_file)
            if session and session.get("homeserver") == hs and whoami_ok(
                hs, session["access_token"], session["user_id"]
            ):
                access_token = session["access_token"]
                user_id = session["user_id"]
                device_id = session["device_id"]
            else:
                if not username or not password:
                    return {
                        "success": False,
                        "reason": "No valid saved session; username/password required for first login.",
                    }
                access_token, user_id, device_id = login_password(hs, username, password)
                save_session(session_file, hs, user_id, device_id, access_token)

            client = build_nio_client(hs, user_id, device_id, access_token, "/app/nio_store")
            try:
                if client.should_upload_keys:
                    await client.keys_upload()

                verified = None
                if recovery_key:
                    verified = cross_sign_device(hs, access_token, user_id, device_id, recovery_key)

                joined = await client.join(room_id)
                if not isinstance(joined, JoinResponse):
                    return {"success": False, "reason": "Join failed: {0}".format(joined)}

                await client.sync(timeout=30000, full_state=True)

                room_obj = client.rooms.get(joined.room_id)
                if room_obj is None:
                    return {"success": False, "reason": "Room not found after sync"}
                if not room_obj.encrypted:
                    return {
                        "success": False,
                        "reason": "Room is not encrypted. Enable encryption in room settings first.",
                    }

                result = await client.room_send(
                    room_id=joined.room_id,
                    message_type="m.room.message",
                    content={"msgtype": "m.text", "body": message},
                    ignore_unverified_devices=True,
                )
                await client.sync(timeout=5000)

                return {
                    "success": True,
                    "user_id": user_id,
                    "device_id": device_id,
                    "cross_signed": verified,
                    "room_id": joined.room_id,
                    "event_id": getattr(result, "event_id", str(result)),
                }
            finally:
                await client.close()

        return asyncio.run(_run())

    def execute_python(self, code, homeserver="", room="", username="", password="", recovery_key=""):
        f = StringIO()

        def custom_print(*args, **kwargs):
            return print(*args, file=f, **kwargs)

        # Всё, что нужно для ad-hoc отладки, доступно прямо в коде без импортов:
        # matrix_client (модуль), все его функции по имени, nio-примитивы,
        # asyncio, json, requests, а также username/password/recovery_key/
        # homeserver/room, которые пришли из auth-профиля и параметров ноды.
        globals_copy = globals().copy()
        globals_copy.update(vars(matrix_client))
        globals_copy["print"] = custom_print
        globals_copy["self"] = self
        globals_copy["asyncio"] = asyncio
        globals_copy["json"] = json
        globals_copy["nio"] = nio
        globals_copy["JoinResponse"] = JoinResponse
        globals_copy["homeserver"] = homeserver
        globals_copy["room"] = room
        globals_copy["username"] = username
        globals_copy["password"] = password
        globals_copy["recovery_key"] = recovery_key

        try:
            exec(code, globals_copy)  # nosec
        except SystemExit:
            pass
        except Exception as e:
            return {"success": False, "message": "Exception: {0}".format(e)}

        s = f.getvalue()
        f.close()

        try:
            return {"success": True, "message": json.loads(s.strip())}
        except Exception:
            return {"success": True, "message": s.strip()}


if __name__ == "__main__":
    MatrixCrypto.run()
