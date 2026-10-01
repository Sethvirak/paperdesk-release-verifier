"""Test-only external-access boundary, installed before production imports."""

import builtins
from contextlib import ExitStack, contextmanager
import io
import os
from pathlib import Path
import socket
import subprocess
import urllib.request
from unittest import mock


@contextmanager
def external_access_blocked():
    """Block network, processes, inherited credentials and known cache files.

    The yielded list records attempted boundary crossings even when production
    code catches the assertion. Callers must verify that the list stays empty.
    Patches are restored before unrelated test cases resume their local work.
    """
    attempts = []
    configured = [Path(value).resolve() for name in ("AZURE_CONFIG_DIR", "GH_CONFIG_DIR", "CLOUDSDK_CONFIG")
                  if (value := os.environ.get(name))]
    def credential_env(name):
        name = name.upper()
        return (any(part in name for part in ("TOKEN", "SECRET", "PASSWORD", "CONNECTION_STRING", "DATABASE_URL"))
                or name.startswith(("AZURE_", "ARM_", "AWS_", "PGHOST", "PGUSER", "PGPORT", "PGDATABASE", "PGPASS"))
                or name in {"GOOGLE_APPLICATION_CREDENTIALS", "SSH_AUTH_SOCK", "SSH_AGENT_PID"})
    clean_environment = {name: value for name, value in os.environ.items() if not credential_env(name)}

    def deny(kind):
        def blocked(*args, **kwargs):
            attempts.append(kind)
            raise AssertionError("offline qualification blocked " + kind)
        return blocked

    def safe_open(original):
        def checked(file, *args, **kwargs):
            if isinstance(file, (str, bytes, os.PathLike)):
                path = Path(os.fsdecode(file)).resolve()
                parts = {part.lower() for part in path.parts}
                if (parts.intersection({".azure", ".aws", ".kube", ".ssh", ".netrc", "_netrc", ".git-credentials", "gcloud"})
                        or any(path == root or root in path.parents for root in configured)):
                    deny("credential-cache access")()
            return original(file, *args, **kwargs)
        return checked

    with ExitStack() as stack:
        stack.enter_context(mock.patch.dict(os.environ, clean_environment, clear=True))
        for owner, name, kind in (
            (socket.socket, "connect", "network"), (socket.socket, "connect_ex", "network"),
            (socket, "create_connection", "network"),
            (urllib.request, "urlopen", "network"), (urllib.request.OpenerDirector, "open", "network"),
            (subprocess, "run", "child process"), (subprocess, "Popen", "child process"),
            (os, "system", "child process"),
        ):
            stack.enter_context(mock.patch.object(owner, name, new=deny(kind)))
        for owner, name in ((builtins, "open"), (io, "open"), (os, "open")):
            stack.enter_context(mock.patch.object(owner, name, new=safe_open(getattr(owner, name))))
        yield attempts
