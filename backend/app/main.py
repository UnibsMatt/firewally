import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from . import db
from .firewall import TRUE, Iptables, IptablesError, render
from .manager import ConflictError, Manager
from .models import NetworkIn, ReorderIn, RuleIn, ServiceIn, SettingsIn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("hti")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
STATIC_DIR = Path(__file__).parent / "static"

ipt = Iptables()
manager = Manager(ipt)
security = HTTPBasic(realm="HTI Firewall")


def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    user_ok = secrets.compare_digest(creds.username.encode(), ADMIN_USER.encode())
    pass_ok = bool(ADMIN_PASSWORD) and secrets.compare_digest(creds.password.encode(), ADMIN_PASSWORD.encode())
    if not (user_ok and pass_ok):
        raise HTTPException(401, "Invalid credentials", headers={"WWW-Authenticate": 'Basic realm="HTI Firewall"'})
    return creds.username


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not ADMIN_PASSWORD:
        raise RuntimeError("ADMIN_PASSWORD must be set")
    db.init_db()
    log.info("iptables backend: %s", ipt.mode)
    if os.environ.get("APPLY_ON_START", "true").lower() in TRUE:
        script = db.last_applied_script()
        if script:
            try:
                manager.reapply(script)
                log.info("last applied ruleset re-applied")
            except IptablesError as e:
                log.error("could not re-apply last ruleset: %s", e)
    yield


app = FastAPI(title="HTI Firewall Manager", lifespan=lifespan)
api = APIRouter(prefix="/api", dependencies=[Depends(require_auth)])
ui = APIRouter(dependencies=[Depends(require_auth)])


def current_script() -> tuple[str, list[str], dict]:
    with db.connect() as c:
        networks = {r["id"]: db.row(r) for r in c.execute("SELECT * FROM networks")}
        services = {r["id"]: db.row(r) for r in c.execute("SELECT * FROM services")}
        rules = [db.row(r) for r in c.execute("SELECT * FROM rules ORDER BY position, id")]
        settings = db.get_settings(c)
    script, warnings = render(networks, services, rules, settings)
    return script, warnings, settings


# ---------------------------------------------------------------- CRUD
def register_crud(path: str, table: str, model: type, order: str) -> None:
    fields = list(model.model_fields)
    cols, marks = ", ".join(fields), ", ".join("?" * len(fields))
    sets = ", ".join(f"{f} = ?" for f in fields)

    @api.get(f"/{path}", name=f"list_{table}")
    def list_items():
        with db.connect() as c:
            return [db.row(r) for r in c.execute(f"SELECT * FROM {table} ORDER BY {order}")]

    @api.post(f"/{path}", status_code=201, name=f"create_{table}")
    def create_item(item: model):
        data = item.model_dump()
        try:
            with db.connect() as c:
                if table == "rules":
                    pos = c.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM rules").fetchone()[0]
                    cur = c.execute(f"INSERT INTO rules ({cols}, position) VALUES ({marks}, ?)",
                                    [*data.values(), pos])
                else:
                    cur = c.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", list(data.values()))
                return {"id": cur.lastrowid, **data}
        except sqlite3.IntegrityError as e:
            raise HTTPException(409, _integrity_message(e))

    @api.put(f"/{path}/{{item_id}}", name=f"update_{table}")
    def update_item(item_id: int, item: model):
        data = item.model_dump()
        try:
            with db.connect() as c:
                cur = c.execute(f"UPDATE {table} SET {sets} WHERE id = ?", [*data.values(), item_id])
                if cur.rowcount == 0:
                    raise HTTPException(404, "Not found")
                return {"id": item_id, **data}
        except sqlite3.IntegrityError as e:
            raise HTTPException(409, _integrity_message(e))

    @api.delete(f"/{path}/{{item_id}}", status_code=204, name=f"delete_{table}")
    def delete_item(item_id: int):
        try:
            with db.connect() as c:
                if c.execute(f"DELETE FROM {table} WHERE id = ?", (item_id,)).rowcount == 0:
                    raise HTTPException(404, "Not found")
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Still used by one or more rules")


def _integrity_message(e: sqlite3.IntegrityError) -> str:
    msg = str(e)
    if "UNIQUE" in msg:
        return "Name already exists"
    if "FOREIGN KEY" in msg:
        return "Referenced network or service does not exist"
    return msg


register_crud("networks", "networks", NetworkIn, "name")
register_crud("services", "services", ServiceIn, "name")
register_crud("rules", "rules", RuleIn, "position, id")


@api.post("/rules/reorder")
def reorder_rules(body: ReorderIn):
    with db.connect() as c:
        c.executemany("UPDATE rules SET position = ? WHERE id = ?", [(i, rid) for i, rid in enumerate(body.ids)])
    return {"ok": True}


# ---------------------------------------------------------------- settings / apply
@api.get("/settings")
def get_settings():
    with db.connect() as c:
        return db.get_settings(c)


@api.put("/settings")
def put_settings(body: SettingsIn):
    with db.connect() as c:
        db.save_settings(c, body.model_dump())
    return body


@api.get("/preview")
def preview():
    script, warnings, _ = current_script()
    return {"script": script, "warnings": warnings}


@api.get("/status")
def status():
    script, _, _ = current_script()
    pending = manager.pending_info()
    reference = pending["script"] if pending else db.last_applied_script()
    if pending:
        pending.pop("script")
    return {
        "backend": ipt.mode,
        "dry_run": ipt.dry_run,
        "pending": pending,
        "dirty": script != reference,
        "never_applied": reference is None,
    }


@api.post("/apply")
def apply(user: str = Depends(require_auth)):
    script, _, settings = current_script()
    try:
        return manager.apply(script, user, settings["confirm_timeout"])
    except IptablesError as e:
        raise HTTPException(400, f"iptables rejected the ruleset: {e}")
    except ConflictError as e:
        raise HTTPException(409, str(e))


@api.post("/confirm")
def confirm(user: str = Depends(require_auth)):
    try:
        return manager.confirm(user)
    except ConflictError as e:
        raise HTTPException(409, str(e))


@api.post("/rollback")
def rollback(user: str = Depends(require_auth)):
    try:
        return manager.rollback(user)
    except ConflictError as e:
        raise HTTPException(409, str(e))
    except IptablesError as e:
        raise HTTPException(500, f"Rollback failed: {e}")


@api.get("/live", response_class=PlainTextResponse)
def live():
    return ipt.listing()


@api.get("/history")
def history():
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM history ORDER BY id DESC LIMIT 50")]


# ---------------------------------------------------------------- UI
@ui.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@ui.get("/static/{name}", include_in_schema=False)
def static(name: str):
    if name not in {"app.js", "style.css"}:
        raise HTTPException(404)
    return FileResponse(STATIC_DIR / name)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


app.include_router(api)
app.include_router(ui)
