"""FastAPI 入口：JSON API + 简洁网页。"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import analyzer, compare as compare_mod, database, licenses, reviews as reviews_mod

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
SAMPLE_PATH = STATIC_DIR / "examples" / "sample-manifest.json"
SAMPLE_CYCLONEDX_PATH = STATIC_DIR / "examples" / "sample-cyclonedx.json"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时初始化 SQLite（建库建表）
    database.init_db()
    yield


app = FastAPI(
    title="许可证依赖冲突审计台",
    description=(
        "上传包含包名、版本、许可证与依赖边的 manifest，或直接提交 CycloneDX JSON"
        "（自动识别 bomFormat / components / dependencies，按 bom-ref 映射节点、"
        "按 ref/dependsOn 还原依赖边），系统规范化节点后按许可证兼容矩阵计算传递约束，"
        "标出每个冲突的最短依赖路径，支持按包筛选与 JSON 导出。"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


class AuditRequest(BaseModel):
    manifest: Dict[str, Any] = Field(
        ..., description="待审计的 manifest 对象（也支持 CycloneDX BOM，自动识别）"
    )
    name: Optional[str] = Field(None, description="本次审计的名称（可选）")


class ReviewCreateRequest(BaseModel):
    audit_id: int = Field(..., description="冲突条目所在的审计 id")
    conflict_id: str = Field(..., description="冲突条目 id（如 C001）")
    note: str = Field("", description="复核备注（可选）")
    expires_at: Optional[str] = Field(
        None, description="标记失效时间（ISO 8601 或 YYYY-MM-DD；留空则长期有效）"
    )


def _audit_payload(manifest: Any, name: Optional[str]) -> Dict[str, Any]:
    if not isinstance(manifest, dict):
        raise HTTPException(status_code=422, detail="manifest 必须是 JSON 对象。")
    result = analyzer.analyze_manifest(manifest, name or "uploaded-manifest")
    if result.get("status") == "error":
        raise HTTPException(status_code=422, detail=result.get("error", "manifest 无法解析。"))
    audit_id = database.save_audit(result, manifest)
    result["audit_id"] = audit_id
    # 附着跨审计复核标记（仅影响响应，不改写已持久化的审计 JSON）
    return reviews_mod.attach_reviews(result)


# --- JSON API ---------------------------------------------------------------


@app.post(
    "/api/audit",
    tags=["audit"],
    summary="审计 manifest（JSON 请求体，自动识别 CycloneDX BOM）",
)
def audit_manifest(payload: AuditRequest) -> Dict[str, Any]:
    manifest = dict(payload.manifest)
    if payload.name:
        manifest.setdefault("name", payload.name)
    return _audit_payload(manifest, payload.name)


@app.post("/api/audit/upload", tags=["audit"], summary="上传 manifest 文件审计")
async def upload_manifest(
    file: UploadFile = File(..., description="manifest JSON 文件"),
    name: Optional[str] = None,
) -> Dict[str, Any]:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=422, detail="上传文件为空。")
    try:
        manifest = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="无法解析 JSON 文件：%s" % exc)
    default_name = name or Path(file.filename or "uploaded-manifest").stem
    return _audit_payload(manifest, default_name)


@app.get("/api/audits", tags=["audit"], summary="历史审计列表")
def list_audits(limit: int = 20) -> Dict[str, Any]:
    limit = max(1, min(limit, 100))
    return {"items": database.list_audits(limit)}


@app.get(
    "/api/audits/compare/{base_id}/{target_id}",
    tags=["audit"],
    summary="对比两次审计（按包名+版本配对节点与冲突，纯只读）",
)
def compare_audits(base_id: int, target_id: int) -> Dict[str, Any]:
    if base_id == target_id:
        raise HTTPException(status_code=400, detail="请选择两条不同的审计记录进行对比：%d 与 %d 相同。" % (base_id, target_id))
    missing = [
        aid for aid in (base_id, target_id)
        if not database.audit_exists(aid)
    ]
    if missing:
        raise HTTPException(
            status_code=404,
            detail="审计记录不存在：%s。对比为只读操作，不会创建新审计。"
            % "、".join("#%d" % aid for aid in missing),
        )
    base_result = database.get_audit(base_id)
    target_result = database.get_audit(target_id)
    return compare_mod.compare_audits(base_result, target_result)


@app.get("/api/audits/{audit_id}", tags=["audit"], summary="获取某次审计结果（支持按包筛选/导出）")
def get_audit(
    audit_id: int,
    package: Optional[str] = None,
    download: bool = False,
) -> Any:
    result = database.get_audit(audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="审计记录不存在：%s" % audit_id)
    result = analyzer.filter_result(result, package)
    # 附着当前有效的跨审计复核标记（指纹一致且未过期/未撤销）
    result = reviews_mod.attach_reviews(result)
    if download:
        filename = "audit-%s%s.json" % (
            audit_id,
            ("-" + package.strip().lower().replace("/", "_")) if package else "",
        )
        return JSONResponse(
            result,
            headers={"Content-Disposition": 'attachment; filename="%s"' % filename},
        )
    return result


@app.delete("/api/audits/{audit_id}", tags=["audit"], summary="删除某次审计记录")
def delete_audit(audit_id: int) -> Dict[str, Any]:
    if not database.delete_audit(audit_id):
        raise HTTPException(status_code=404, detail="审计记录不存在：%s" % audit_id)
    return {"deleted": audit_id}


# --- 跨审计复核标记 -----------------------------------------------------------


@app.post(
    "/api/reviews",
    tags=["review"],
    status_code=201,
    summary="创建复核标记（按审计中的冲突条目，跨审计按指纹生效）",
)
def create_review(payload: ReviewCreateRequest) -> Dict[str, Any]:
    result = database.get_audit(payload.audit_id)
    if result is None:
        raise HTTPException(status_code=404, detail="审计记录不存在：%s" % payload.audit_id)
    conflict = next(
        (c for c in result.get("conflicts", []) if c.get("id") == payload.conflict_id),
        None,
    )
    if conflict is None:
        raise HTTPException(
            status_code=404,
            detail="审计 #%s 中不存在冲突条目：%s" % (payload.audit_id, payload.conflict_id),
        )
    expires_at: Optional[str] = None
    if payload.expires_at and payload.expires_at.strip():
        try:
            expires_at = reviews_mod.normalize_expires_at(payload.expires_at)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if expires_at <= database.utcnow():
            raise HTTPException(status_code=422, detail="失效时间必须晚于当前时间。")
    ancestor, node, ancestor_token, node_token = reviews_mod.fingerprint_parts(result, conflict)
    fingerprint = reviews_mod.conflict_fingerprint(ancestor, node, ancestor_token, node_token)
    record = database.save_review(
        fingerprint=fingerprint,
        ancestor=ancestor,
        node=node,
        ancestor_license=ancestor_token,
        node_license=node_token,
        note=payload.note.strip(),
        expires_at=expires_at,
    )
    return record


@app.get("/api/reviews", tags=["review"], summary="复核标记记录列表（可按状态/指纹筛选）")
def list_reviews(
    state: Optional[str] = None,
    fingerprint: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    limit = max(1, min(limit, 500))
    try:
        items = database.list_reviews(state=state, fingerprint=fingerprint, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {"items": items}


@app.get("/api/reviews/{review_id}", tags=["review"], summary="获取单条复核标记记录")
def get_review(review_id: int) -> Dict[str, Any]:
    record = database.get_review(review_id)
    if record is None:
        raise HTTPException(status_code=404, detail="复核标记不存在：%s" % review_id)
    return record


@app.post(
    "/api/reviews/{review_id}/revoke",
    tags=["review"],
    summary="撤销复核标记（保留历史记录，条目回到待复核）",
)
def revoke_review(review_id: int) -> Dict[str, Any]:
    record = database.revoke_review(review_id)
    if record is None:
        raise HTTPException(status_code=404, detail="复核标记不存在：%s" % review_id)
    return record


@app.get("/api/matrix", tags=["meta"], summary="许可证兼容矩阵")
def license_matrix() -> Dict[str, Any]:
    return {
        "direction": "parent (分发作品许可证) -> dependency (被依赖代码许可证)",
        "categories": licenses.CATEGORY_LABELS,
        "category_notes": licenses.CATEGORY_NOTES,
        "matrix": licenses.build_matrix(),
    }


@app.get("/api/sample", tags=["meta"], summary="获取内置示例 manifest")
def sample_manifest() -> Dict[str, Any]:
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


@app.get("/api/sample/cyclonedx", tags=["meta"], summary="获取内置 CycloneDX 示例 BOM")
def sample_cyclonedx() -> Dict[str, Any]:
    return json.loads(SAMPLE_CYCLONEDX_PATH.read_text(encoding="utf-8"))


@app.get("/healthz", tags=["meta"], summary="健康检查")
def health() -> Dict[str, str]:
    return {"status": "ok"}


# --- 网页 -------------------------------------------------------------------


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
