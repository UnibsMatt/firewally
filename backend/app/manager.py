"""Apply workflow: test -> snapshot -> atomic apply -> confirm (or automatic rollback) -> persist."""
import logging
import os
import threading
import time

from . import db
from .firewall import Iptables, IptablesError

log = logging.getLogger("hti.manager")

PERSIST_FILE = os.environ.get("PERSIST_FILE", "/host/iptables/rules.v4")


class ConflictError(RuntimeError):
    pass


class Manager:
    def __init__(self, ipt: Iptables) -> None:
        self.ipt = ipt
        self._lock = threading.RLock()
        self._pending: dict | None = None

    def pending_info(self) -> dict | None:
        with self._lock:
            p = self._pending
            if not p:
                return None
            return {"history_id": p["id"], "remaining": max(0, int(p["deadline"] - time.time())), "script": p["script"]}

    def apply(self, script: str, user: str, timeout: int) -> dict:
        with self._lock:
            if self._pending:
                raise ConflictError("A previous change is still waiting for confirmation")
            self.ipt.test(script)
            previous = self.ipt.snapshot()
            try:
                self.ipt.restore(script)
            except IptablesError:
                self._safe_restore(previous)
                raise

            if timeout > 0:
                hid = db.add_history(user, "pending", f"Waiting for confirmation ({timeout}s)", script)
                timer = threading.Timer(timeout, self._auto_rollback, args=(hid,))
                timer.daemon = True
                self._pending = {"id": hid, "deadline": time.time() + timeout, "timer": timer,
                                 "previous": previous, "script": script}
                timer.start()
                return {"status": "pending", "remaining": timeout}

            persisted = self._persist(script)
            db.add_history(user, "applied", persisted, script)
            return {"status": "applied", "message": persisted}

    def confirm(self, user: str) -> dict:
        with self._lock:
            p = self._take_pending()
            persisted = self._persist(p["script"])
            db.set_history_status(p["id"], "applied", f"Confirmed by {user}. {persisted}")
            return {"status": "applied", "message": persisted}

    def rollback(self, user: str) -> dict:
        with self._lock:
            p = self._take_pending()
            self.ipt.restore(p["previous"])
            db.set_history_status(p["id"], "rolled_back", f"Rolled back by {user}")
            return {"status": "rolled_back"}

    def reapply(self, script: str) -> None:
        """Re-apply a known-good ruleset (startup)."""
        with self._lock:
            self.ipt.test(script)
            self.ipt.restore(script)

    def _take_pending(self) -> dict:
        p = self._pending
        if not p:
            raise ConflictError("Nothing is waiting for confirmation")
        p["timer"].cancel()
        self._pending = None
        return p

    def _auto_rollback(self, history_id: int) -> None:
        with self._lock:
            if not self._pending or self._pending["id"] != history_id:
                return
            p = self._take_pending()
            ok = self._safe_restore(p["previous"])
            db.set_history_status(
                history_id, "rolled_back",
                "Not confirmed in time: previous ruleset restored" if ok else "Not confirmed in time: ROLLBACK FAILED, check logs",
            )
            log.warning("change %s not confirmed, rolled back (ok=%s)", history_id, ok)

    def _safe_restore(self, script: str) -> bool:
        try:
            self.ipt.restore(script)
            return True
        except IptablesError:
            log.exception("restoring previous ruleset failed")
            return False

    def _persist(self, script: str) -> str:
        """Write the full live ruleset to the host file (same as `netfilter-persistent save`)."""
        if self.ipt.dry_run or not PERSIST_FILE:
            return "Not persisted (dry-run or PERSIST_FILE unset)."
        directory = os.path.dirname(PERSIST_FILE)
        if not os.path.isdir(directory):
            return f"Not persisted: {directory} is not mounted."
        try:
            content = self.ipt.save_all()
            tmp = os.path.join(directory, ".hti-rules.tmp")
            with open(tmp, "w") as f:
                f.write(content)
            os.chmod(tmp, 0o640)
            os.replace(tmp, PERSIST_FILE)
            with open(os.path.join(directory, "hti-managed.rules"), "w") as f:
                f.write(script)
            return f"Saved to host {os.path.basename(PERSIST_FILE)}."
        except (OSError, IptablesError) as e:
            log.exception("persist failed")
            return f"Applied but NOT persisted: {e}"
