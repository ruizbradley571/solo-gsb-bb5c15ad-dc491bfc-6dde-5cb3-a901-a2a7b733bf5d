"""根包退役预演（纯只读计算）。

**根包**定义为依赖图中没有入边的包（没有任何「使用方」指向它的包），
即依赖图中没有任何边以其为 target 的节点。

给定一条已保存审计的结果与一组拟退役的根包 id，本模块沿
**使用方 → 被依赖方** 的边，从**剩余根包**重新做可达性计算，给出：

* ``retired_roots``  —— 本次模拟退役的根包；
* ``lost_packages``  —— 退役后失去可达性的包（不含已退役根本身）；
* ``shared_packages`` —— 原本同时被「某个退役根包」与「某个剩余根包」
  共用、退役后仍被剩余根包保留下来的包；
* ``orphan_packages`` —— 在原图中本就不被任何根包可达的孤立包（不受退役影响）；
* ``vanished_conflicts`` —— 随失联包一起消失的许可证冲突/告警，
  每条附原最短路径与路径上首个失联节点，便于核对冲突为何消失；
* ``remaining_conflicts`` —— 退役后仍然存在的冲突/告警计数与条目。

整个过程只读取审计结果字典，不写库、不创建审计、不触碰复核标记；
校验失败（非根包、重复选择、退役全部根包等）抛出 :class:`RetireError`，
由 API 层映射为明确的 4xx 错误。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set

# --- 校验错误（API 层映射为对应 HTTP 状态码） ---------------------------------


class RetireError(ValueError):
    """预演校验错误基类；``status`` 为建议的 HTTP 状态码。"""

    status = 422


class AuditNotFound(RetireError):
    """审计记录不存在。"""

    status = 404


class InvalidSelection(RetireError):
    """选择内容非法（非列表、含非根包、重复选择等）。"""


class AllRootsRetired(RetireError):
    """退役了全部根包，预演后无任何根包可重算可达集合。"""

    status = 400


# --- 图与可达性 ---------------------------------------------------------------


def _node_map(result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    nodes: Dict[str, Dict[str, Any]] = {}
    for node in result.get("nodes") or []:
        nid = node.get("id")
        if nid is not None:
            nodes[str(nid)] = node
    return nodes


def build_adjacency(
    node_ids: Set[str], edges: Any
) -> Dict[str, List[str]]:
    """由审计结果的 edges 构造使用方 -> 被依赖方 邻接表（去重，兼容环）。"""
    adjacency: Dict[str, List[str]] = {nid: [] for nid in node_ids}
    seen: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
    for edge in edges or []:
        if not isinstance(edge, dict):
            continue
        source = edge.get("source")
        target = edge.get("target")
        if source is None or target is None:
            continue
        source, target = str(source), str(target)
        # 只统计已声明节点之间的边（历史数据兜底）
        if source not in adjacency or target not in adjacency:
            continue
        if target in seen[source]:
            continue
        seen[source].add(target)
        adjacency[source].append(target)
    return adjacency


def find_roots(node_ids: Set[str], adjacency: Dict[str, List[str]]) -> List[str]:
    """根包：没有入边的节点（结果按 id 排序，保证展示稳定）。"""
    has_incoming: Set[str] = set()
    for targets in adjacency.values():
        has_incoming.update(targets)
    return sorted(node_ids - has_incoming)


def reachable_from(
    roots: List[str], adjacency: Dict[str, List[str]]
) -> Set[str]:
    """从一组根出发沿使用方 → 被依赖方的边计算可达集合（含根本身，兼容环）。"""
    reachable: Set[str] = set()
    queue: deque[str] = deque()
    for root in roots:
        if root in adjacency and root not in reachable:
            reachable.add(root)
            queue.append(root)
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, []):
            if nxt not in reachable:
                reachable.add(nxt)
                queue.append(nxt)
    return reachable


def _reachable_by_root(
    roots: List[str], adjacency: Dict[str, List[str]]
) -> Dict[str, Set[str]]:
    """每个根包单独的可达集合（含根本身）。"""
    return {root: reachable_from([root], adjacency) for root in roots}


# --- 节点摘要 ----------------------------------------------------------------


def _node_brief(node: Optional[Dict[str, Any]], nid: str) -> Dict[str, Any]:
    if node is None:
        name, _, version = nid.partition("@")
        return {
            "id": nid,
            "name": name or nid,
            "version": version,
            "version_unspecified": True,
            "license_display": None,
            "license": None,
            "license_category": None,
        }
    return {
        "id": str(node.get("id") or nid),
        "name": node.get("name"),
        "version": node.get("version"),
        "version_unspecified": node.get("version_unspecified", False),
        "license_display": node.get("license_display"),
        "license": node.get("license"),
        "license_category": node.get("license_category"),
        "conflict_count": node.get("conflict_count", 0),
    }


def _roots_overview(
    roots: List[str],
    nodes: Dict[str, Dict[str, Any]],
    per_root: Dict[str, Set[str]],
) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for root in roots:
        reach = per_root.get(root, {root})
        items.append(
            {
                **_node_brief(nodes.get(root), root),
                "reachable_count": len(reach),
                # 该根独占的下游包数（只被这一个根可达的非根节点），
                # 预演时用来提示退役影响面
                "reachable_packages": sorted(reach - {root}),
            }
        )
    return items


# --- 冲突分类 ----------------------------------------------------------------


def _conflict_endpoints_reachable(conflict: Dict[str, Any], reachable: Set[str]) -> bool:
    return (
        str(conflict.get("ancestor") or "") in reachable
        and str(conflict.get("node") or "") in reachable
    )


def _path_status(conflict: Dict[str, Any], reachable: Set[str]) -> Dict[str, Any]:
    """标注原最短路径上每个节点退役后的可达情况，并找出首个失联节点。"""
    path = [str(p) for p in (conflict.get("path") or [])]
    on_path = [
        {
            "id": nid,
            "reachable": nid in reachable,
        }
        for nid in path
    ]
    first_lost = next((nid for nid in path if nid not in reachable), None)
    return {"path": on_path, "first_lost_node": first_lost}


def _conflict_brief(conflict: Dict[str, Any]) -> Dict[str, Any]:
    """不改动原始冲突对象，拷贝一份用于预演响应（剥离附着的复核标记）。"""
    keys = (
        "id",
        "kind",
        "severity",
        "status",
        "ancestor",
        "node",
        "ancestor_license",
        "node_license",
        "distance",
        "path",
        "reason",
    )
    return {key: conflict.get(key) for key in keys if key in conflict}


# --- 入口：根包清单 -----------------------------------------------------------


def roots_overview(result: Dict[str, Any]) -> Dict[str, Any]:
    """列出一条审计的根包及每个根包的可达影响面（供网页勾选）。"""
    nodes = _node_map(result)
    adjacency = build_adjacency(set(nodes), result.get("edges"))
    roots = find_roots(set(nodes), adjacency)
    per_root = _reachable_by_root(roots, adjacency)
    baseline = reachable_from(roots, adjacency)
    return {
        "kind": "root-retirement-roots",
        "read_only": True,
        "audit_id": result.get("audit_id"),
        "manifest_name": result.get("manifest_name"),
        "source_format": result.get("source_format"),
        "summary": {
            "packages": len(nodes),
            "edges": len(result.get("edges") or []),
            "root_packages": len(roots),
            "reachable_packages": len(baseline),
            "unreachable_packages": len(set(nodes) - baseline),
        },
        "roots": _roots_overview(roots, nodes, per_root),
        "graph": {
            "direction": "使用方(consumer) -> 被依赖方(dependency)",
            "root_definition": "根包：没有任何入边（没有其他包依赖它）的包。",
        },
    }


# --- 入口：预演 ---------------------------------------------------------------


def _validate_selection(
    retired: Any,
    roots: List[str],
    nodes: Dict[str, Dict[str, Any]],
    audit_id: Any,
) -> List[str]:
    """校验拟退役选择，返回规范化（去重保序、排序）后的根包 id 列表。"""
    if not isinstance(retired, list):
        raise InvalidSelection("retire 必须是根包 id 的数组（可为空数组表示不退役任何根包）。")
    normalized: List[str] = []
    seen: Set[str] = set()
    duplicates: List[str] = []
    for item in retired:
        nid = str(item).strip() if item is not None else ""
        if not nid:
            raise InvalidSelection("retire 数组中存在空的包 id，请去掉后重试。")
        if nid in seen:
            duplicates.append(nid)
            continue
        seen.add(nid)
        normalized.append(nid)
    if duplicates:
        raise InvalidSelection(
            "退役选择存在重复的根包：%s。请去掉重复勾选后重试。"
            % "、".join(sorted(set(duplicates)))
        )

    root_set = set(roots)
    non_roots = [
        nid
        for nid in normalized
        if nid in nodes and nid not in root_set
    ]
    unknown = [nid for nid in normalized if nid not in nodes]
    if unknown:
        raise InvalidSelection(
            "选择的包不存在于审计 #%s：%s。请只勾选页面列出的根包。"
            % (audit_id, "、".join(sorted(unknown)))
        )
    if non_roots:
        raise InvalidSelection(
            "以下包不是根包（存在入边，即仍被其他包依赖），不能作为退役对象：%s。"
            "根包定义为没有入边的包。" % "、".join(sorted(non_roots))
        )
    return normalized


def simulate_retirement(
    result: Dict[str, Any],
    retired: List[str],
    audit_id: Optional[Any] = None,
) -> Dict[str, Any]:
    """对一条审计结果执行根包退役预演（纯只读）。

    :param result: ``database.get_audit`` / ``analyzer.analyze_manifest`` 产物；
    :param retired: 拟退役的根包 id 列表；
    :param audit_id: 仅用于错误信息（结果字典里缺 audit_id 时兜底）。
    """
    nodes = _node_map(result)
    adjacency = build_adjacency(set(nodes), result.get("edges"))
    roots = find_roots(set(nodes), adjacency)
    shown_audit_id = result.get("audit_id", audit_id)

    retired_ids = _validate_selection(retired, roots, nodes, shown_audit_id)
    retired_set = set(retired_ids)
    if not roots:
        raise InvalidSelection(
            "审计 #%s 的依赖图中没有根包（所有节点都有入边，通常意味着图只由环构成），"
            "无法进行根包退役预演。" % shown_audit_id
        )
    if retired_set == set(roots):
        raise AllRootsRetired(
            "不能退役全部 %d 个根包：退役后将没有任何根包可供重算可达集合，"
            "请至少保留一个根包。" % len(roots)
        )

    remaining_roots = [r for r in roots if r not in retired_set]

    # 原图中每个根单独的可达集合（用于判断“共用”与“失联的归因”）
    reach_by_root = _reachable_by_root(roots, adjacency)

    # 基线：所有根包（未退役时）的可达集合
    baseline_reachable = reachable_from(roots, adjacency)
    # 预演后：仅从剩余根包重算
    remaining_reachable = reachable_from(remaining_roots, adjacency)

    # 退役根可达（任一退役根）的节点集合，用于识别“被退役根波及”
    retired_roots_reachable: Set[str] = set()
    for root in retired_ids:
        retired_roots_reachable |= reach_by_root.get(root, {root})

    # 1) 失联包：原本可达、预演后不再可达（排除退役根本身，单独列出）
    lost_ids = sorted(
        (baseline_reachable - retired_set) - remaining_reachable
    )
    # 2) 仍被共用的包：同时被退役根与剩余根可达，预演后依然可达
    shared_ids = sorted(
        (retired_roots_reachable & remaining_reachable) - retired_set
    )
    # 3) 原图就不可达的孤立包（不属于任何根的子图），仅作说明
    orphan_ids = sorted(set(nodes) - baseline_reachable)

    # 每个失联包原本由哪些（即将退役的）根可达
    lost_packages: List[Dict[str, Any]] = []
    for nid in lost_ids:
        former_roots = sorted(
            root for root in retired_ids if nid in reach_by_root.get(root, set())
        )
        entry = _node_brief(nodes.get(nid), nid)
        entry["former_root_packages"] = former_roots
        lost_packages.append(entry)

    shared_packages: List[Dict[str, Any]] = []
    for nid in shared_ids:
        entry = _node_brief(nodes.get(nid), nid)
        entry["retired_root_packages"] = sorted(
            root for root in retired_ids if nid in reach_by_root.get(root, set())
        )
        entry["remaining_root_packages"] = sorted(
            root for root in remaining_roots if nid in reach_by_root.get(root, set())
        )
        shared_packages.append(entry)

    # 4) 冲突/告警分类：预演后 ancestor 与 node 均仍可达 ⇒ 冲突仍存在；
    #    任一端失联（包括退役根本身）⇒ 冲突随失联包消失。
    vanished_conflicts: List[Dict[str, Any]] = []
    remaining_conflicts: List[Dict[str, Any]] = []
    for conflict in result.get("conflicts") or []:
        brief = _conflict_brief(conflict)
        if _conflict_endpoints_reachable(conflict, remaining_reachable):
            remaining_conflicts.append(brief)
            continue
        path_status = _path_status(conflict, remaining_reachable)
        reasons: List[str] = []
        ancestor = str(conflict.get("ancestor") or "")
        node = str(conflict.get("node") or "")
        if ancestor in retired_set:
            reasons.append("祖先节点 %s 是本次退役的根包" % ancestor)
        if node in retired_set:
            reasons.append("被依赖节点 %s 是本次退役的根包" % node)
        lost_here = path_status["first_lost_node"]
        if not reasons and lost_here is not None:
            reasons.append("原最短路径上的 %s 失去可达性" % lost_here)
        brief["path_status"] = path_status
        brief["vanish_reason"] = "；".join(reasons) or "冲突两端均不再可达"
        vanished_conflicts.append(brief)

    def _sev(items: List[Dict[str, Any]], sev: str) -> int:
        return sum(1 for item in items if item.get("severity") == sev)

    retired_root_items = [
        _node_brief(nodes.get(nid), nid) for nid in sorted(retired_set)
    ]

    return {
        "kind": "root-retirement-rehearsal",
        "read_only": True,
        "audit_id": shown_audit_id,
        "manifest_name": result.get("manifest_name"),
        "source_format": result.get("source_format"),
        "selection": {
            "retired_root_packages": [item["id"] for item in retired_root_items],
            "remaining_root_packages": list(remaining_roots),
        },
        "retired_roots": retired_root_items,
        "lost_packages": lost_packages,
        "shared_packages": shared_packages,
        "orphan_packages": [
            _node_brief(nodes.get(nid), nid) for nid in orphan_ids
        ],
        "vanished_conflicts": vanished_conflicts,
        "remaining_conflicts": remaining_conflicts,
        "summary": {
            "root_packages": len(roots),
            "retired_roots": len(retired_root_items),
            "remaining_roots": len(remaining_roots),
            "reachable_before": len(baseline_reachable),
            "reachable_after": len(remaining_reachable),
            "lost_packages": len(lost_packages),
            "shared_packages": len(shared_ids),
            "orphan_packages": len(orphan_ids),
            "conflicts_before": len(result.get("conflicts") or []),
            "conflicts_vanished": len(vanished_conflicts),
            "conflicts_vanished_errors": _sev(vanished_conflicts, "error"),
            "conflicts_remaining": len(remaining_conflicts),
            "conflicts_remaining_errors": _sev(remaining_conflicts, "error"),
        },
        "graph": {
            "direction": "使用方(consumer) -> 被依赖方(dependency)",
            "root_definition": "根包：没有任何入边（没有其他包依赖它）的包。",
            "note": "预演只读：不创建审计、不改动复核标记，可反复调整退役选择。",
        },
    }
