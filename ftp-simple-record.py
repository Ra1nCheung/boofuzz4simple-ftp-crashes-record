#!/usr/bin/env python3
"""FTP fuzzer (only log crashing inputs)."""

from boofuzz import *
import os

CRASH_DIR = "crashes"
os.makedirs(CRASH_DIR, exist_ok=True)


def crash_callback(target, fuzz_data_logger, session, test_case_id, *args):
    """
    Only triggered when the target crashes.
    Saves the exact payload that caused the crash.
    """
    print(f"[CRASH] Target crashed on test case #{test_case_id}")

    crash_file = f"{CRASH_DIR}/crash_{test_case_id:06d}.bin"
    with open(crash_file, "wb") as f:
        f.write(session.last_send)

    print(f"[CRASH] Payload saved to {crash_file}")


def main():
    """Simple FTP fuzzer that logs *only* crashing inputs."""
    session = Session(
        target=Target(connection=TCPSocketConnection("127.0.0.1", 8021)),
        session_filename="session.sqlite",
        post_test_case_callbacks=[crash_callback],  # only fires when crash
    )

    define_proto(session=session)
    session.fuzz()


def define_proto(session):
    # fmt: off
    user = Request("user", children=(
        String(name="key", default_value="USER"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="anonymous"),
        Static(name="end", default_value="\r\n"),
    ))

    passw = Request("pass", children=(
        String(name="key", default_value="PASS"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="james"),
        Static(name="end", default_value="\r\n"),
    ))

    stor = Request("stor", children=(
        String(name="key", default_value="STOR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))

    retr = Request("retr", children=(
        String(name="key", default_value="RETR"),
        Delim(name="space", default_value=" "),
        String(name="val", default_value="AAAA"),
        Static(name="end", default_value="\r\n"),
    ))
    # fmt: on

    session.connect(user)
    session.connect(user, passw)
    session.connect(passw, stor)
    session.connect(passw, retr)


if __name__ == "__main__":
    main()
