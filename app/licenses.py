"""许可证规范化与许可证兼容矩阵。

兼容方向按 *父项目（派生/分发作品）许可证 -> 依赖许可证* 判定，
即父许可证能否容纳依赖许可证（是否可将依赖代码整合进父作品一起分发）。

覆盖的许可证：
    宽松型 : MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, Unlicense, CC0-1.0
    弱 copyleft : MPL-2.0, LGPL-2.1, LGPL-3.0
    强 copyleft : GPL-2.0, GPL-3.0, AGPL-3.0
    专有 : Proprietary

未识别的许可证一律保留原文并标记 unknown，按“需人工确认”告警处理。
"""

from __future__ import annotations

from functools import lru_cache
from typing import Dict, List, Optional, Tuple

# --- 许可证元数据 -----------------------------------------------------------

PERMISSIVE = "permissive"
WEAK_COPYLEFT = "weak-copyleft"
STRONG_COPYLEFT = "strong-copyleft"
PROPRIETARY = "proprietary"
UNKNOWN = "unknown"

CATEGORIES: Dict[str, str] = {
    "MIT": PERMISSIVE,
    "ISC": PERMISSIVE,
    "BSD-2-Clause": PERMISSIVE,
    "BSD-3-Clause": PERMISSIVE,
    "Apache-2.0": PERMISSIVE,
    "Unlicense": PERMISSIVE,
    "CC0-1.0": PERMISSIVE,
    "MPL-2.0": WEAK_COPYLEFT,
    "LGPL-2.1": WEAK_COPYLEFT,
    "LGPL-3.0": WEAK_COPYLEFT,
    "GPL-2.0": STRONG_COPYLEFT,
    "GPL-3.0": STRONG_COPYLEFT,
    "AGPL-3.0": STRONG_COPYLEFT,
    "Proprietary": PROPRIETARY,
}

CATEGORY_LABELS: Dict[str, str] = {
    PERMISSIVE: "宽松型",
    WEAK_COPYLEFT: "弱 Copyleft",
    STRONG_COPYLEFT: "强 Copyleft",
    PROPRIETARY: "专有",
    UNKNOWN: "未知",
}

CATEGORY_NOTES: Dict[str, str] = {
    PERMISSIVE: "宽松许可证，基本不向集成方施加分发约束。",
    WEAK_COPYLEFT: "弱 copyleft：库本身修改需开源，动态链接通常可被专有作品使用。",
    STRONG_COPYLEFT: "强 copyleft：整体派生作品须以同一许可证开源，排斥专有代码。",
    PROPRIETARY: "专有许可证，不允许自由再分发/修改，能否使用需逐项确认。",
    UNKNOWN: "未在矩阵中识别，无法自动判定兼容性，需要人工确认。",
}

# 规范标识的小写形式 -> 规范标识（gpl-2.0 -> GPL-2.0 等）
_CANONICAL_LOWER = {token.lower(): token for token in CATEGORIES}

# 常见别名 -> 规范 SPDX 标识
_ALIASES: Dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "isc": "ISC",
    "isc license": "ISC",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd2": "BSD-2-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd3": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "apache": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "mpl": "MPL-2.0",
    "mpl2": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl": "LGPL-3.0",
    "lgpl2": "LGPL-2.1",
    "lgpl-2": "LGPL-2.1",
    "lgpl 2.1": "LGPL-2.1",
    "lgpl-2.1-only": "LGPL-2.1",
    "lgpl3": "LGPL-3.0",
    "lgplv2": "LGPL-2.1",
    "lgplv3": "LGPL-3.0",
    "lgpl-3": "LGPL-3.0",
    "lgpl 3.0": "LGPL-3.0",
    "lgpl-3.0-only": "LGPL-3.0",
    "gpl": "GPL-3.0",
    "gpl2": "GPL-2.0",
    "gpl-2": "GPL-2.0",
    "gpl 2": "GPL-2.0",
    "gpl 2.0": "GPL-2.0",
    "gplv2": "GPL-2.0",
    "gpl-2.0-only": "GPL-2.0",
    "gpl3": "GPL-3.0",
    "gpl-3": "GPL-3.0",
    "gpl 3": "GPL-3.0",
    "gpl 3.0": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gpl-3.0-only": "GPL-3.0",
    "agpl": "AGPL-3.0",
    "agpl3": "AGPL-3.0",
    "agpl-3": "AGPL-3.0",
    "agpl 3": "AGPL-3.0",
    "agpl 3.0": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "agpl-3.0-only": "AGPL-3.0",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    "cc0 1.0 universal": "CC0-1.0",
    "public domain": "CC0-1.0",
    "proprietary": "Proprietary",
    "commercial": "Proprietary",
    "all rights reserved": "Proprietary",
    "closed": "Proprietary",
    "closed source": "Proprietary",
}


def normalize_license(raw: object) -> Tuple[str, str, bool]:
    """把许可证文本规范化为 SPDX 标识。

    返回 ``(display, token, known)``：

    * display — 始终保留用户原文（去除首尾空白后），未知时原样展示；
    * token   — 规范标识，未知时为原文小写压缩形式；
    * known   — 是否被矩阵识别。
    """
    text = "" if raw is None else str(raw).strip()
    display = text if text else "UNLICENSED"
    key = " ".join(text.lower().split())
    # 规范标识本身的小写连字符形式（gpl-2.0 / apache-2.0 / bsd-2-clause …）
    if key in _CANONICAL_LOWER:
        return display, _CANONICAL_LOWER[key], True
    canonical = _ALIASES.get(key)
    if canonical:
        return display, canonical, True
    # 形如 "GPL-2.0-or-later" 这类带后缀的 SPDX 写法按该版本处理
    stripped = key.removesuffix("-or-later").removesuffix("-only")
    canonical = (
        _ALIASES.get(stripped)
        or _CANONICAL_LOWER.get(stripped)
        or (stripped if stripped in CATEGORIES else None)
    )
    if canonical:
        return display, canonical, True
    if not text:
        return display, "unlicensed", False
    return display, key.replace(" ", "_"), False


# --- 兼容性判定 -------------------------------------------------------------

OK = "ok"
CONFLICT = "conflict"
WARNING = "warning"


def imposes_constraint(token: str) -> bool:
    """该许可证是否会向集成它的父作品施加传递约束。"""
    return CATEGORIES.get(token) in (
        WEAK_COPYLEFT,
        STRONG_COPYLEFT,
        PROPRIETARY,
        UNKNOWN,
    )


def compatibility(parent_token: str, dep_token: str) -> Tuple[str, str]:
    """判定 *父许可证 parent* 能否容纳 *依赖许可证 dep*。

    返回 ``(状态, 中文原因)``，状态为 ok / conflict / warning。
    """
    parent_cat = CATEGORIES.get(parent_token, UNKNOWN)
    dep_cat = CATEGORIES.get(dep_token, UNKNOWN)

    if parent_cat == UNKNOWN or dep_cat == UNKNOWN:
        return (
            WARNING,
            "涉及未在兼容矩阵中识别的许可证，无法自动判定，需要人工确认。",
        )

    if parent_token == dep_token:
        return OK, "同一许可证，天然兼容。"

    if parent_cat == PERMISSIVE:
        # 宽松许可证可容纳几乎一切，但专有依赖仍需单独确认授权
        if dep_cat == PROPRIETARY:
            return WARNING, "父许可证为宽松型，但依赖为专有许可证，使用与再分发需单独确认授权。"
        return OK, "宽松许可证对集成依赖无 copyleft 约束。"

    if parent_token == "MPL-2.0":
        if dep_cat == PERMISSIVE:
            return OK, "MPL-2.0 允许文件级混用宽松许可证代码。"
        if dep_token == "LGPL-2.1":
            return CONFLICT, "MPL-2.0 与 LGPL-2.1 的条款相互不兼容，无法将两者组合进同一作品。"
        if dep_token in ("GPL-2.0", "AGPL-3.0"):
            return CONFLICT, "MPL-2.0 文件与 %s 组合时升级条款不被接受，属于不兼容组合。" % dep_token
        if dep_token in ("LGPL-3.0", "GPL-3.0"):
            return OK, "MPL-2.0 提供“按 GPL/LGPL 二级许可”选项，可与 %s 组合。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "MPL-2.0 要求被覆盖文件保持 MPL 并提供源码，不能并入专有闭源作品。"

    if parent_token == "LGPL-2.1":
        if dep_cat == PERMISSIVE:
            return OK, "LGPL-2.1 作品可以集成宽松许可证代码。"
        if dep_token in ("MPL-2.0", "LGPL-3.0", "GPL-3.0", "AGPL-3.0"):
            return CONFLICT, "LGPL-2.1 作品不能由 %s 代码派生（许可证升级方向不被允许）。" % dep_token
        if dep_token == "GPL-2.0":
            return OK, "LGPL-2.1 允许按 GPL-2.0 二级许可重新发布。"
        if dep_cat == PROPRIETARY:
            return CONFLICT, "LGPL-2.1 不允许将受其覆盖的库代码并入专有作品（仅独立链接例外）。"

    if parent_token == "LGPL-3.0":
        if dep_cat == PERMISSIVE:
            return OK, "LGPL-3.0 作品可以集成宽松许可证代码。"
        if dep_token == "MPL-2.0":
            return OK, "MPL-2.0 可按 GPL 兼容二级许可并入 LGPL-3.0 作品。"
        if dep_token == "LGPL-2.1":
            return OK, "LGPL-3.0 允许纳入早期版本 LGPL-2.1 的代码。"
        if dep_token in ("GPL-3.0", "AGPL-3.0"):
            return OK, "LGPL-3.0 允许按 GPL-3.0/AGPL-3.0 二级许可重新发布。"
        if dep_token == "GPL-2.0":
            return CONFLICT, "GPL-2.0（仅 v2）不能升级到 LGPL-3.0，无法并入 LGPL-3.0 作品。"
        if dep_cat == PROPRIETARY:
            return CONFLICT, "LGPL-3.0 不允许将受其覆盖的库代码并入专有作品（仅独立链接例外）。"

    if parent_token == "GPL-2.0":
        if dep_cat == PERMISSIVE and parent_token != dep_token:
            if dep_token == "Apache-2.0":
                return CONFLICT, "GPL-2.0 与 Apache-2.0 专利条款冲突，不能组合进同一作品。"
            return OK, "宽松许可证代码可被 GPL-2.0 作品吸纳。"
        if dep_token in ("LGPL-2.1",):
            return OK, "LGPL-2.1 可重新许可为 GPL-2.0，可被 GPL-2.0 作品吸纳。"
        if dep_token in (
            "MPL-2.0",
            "LGPL-3.0",
            "GPL-3.0",
            "AGPL-3.0",
        ):
            return CONFLICT, "%s 的要求无法在 GPL-2.0（仅 v2）条款下满足，方向不兼容。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "GPL-2.0 整体作品必须开源，不能与专有代码组合分发。"

    if parent_token == "GPL-3.0":
        if dep_cat == PERMISSIVE:
            return OK, "GPL-3.0 明确兼容宽松许可证（含 Apache-2.0）。"
        if dep_token == "MPL-2.0":
            return OK, "MPL-2.0 提供 GPL 二级许可，可与 GPL-3.0 组合。"
        if dep_token in ("LGPL-2.1", "LGPL-3.0"):
            return OK, "%s 代码可升级到 GPL-3.0 后纳入 GPL-3.0 作品。" % dep_token
        if dep_token in ("GPL-2.0", "AGPL-3.0"):
            return CONFLICT, "%s 不能单向升级到 GPL-3.0（GPLv2-only 不兼容，AGPL 需另行满足网络条款）。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "GPL-3.0 整体作品必须开源，不能与专有代码组合分发。"

    if parent_token == "AGPL-3.0":
        if dep_cat == PERMISSIVE:
            return OK, "AGPL-3.0 兼容宽松许可证（含 Apache-2.0）。"
        if dep_token == "MPL-2.0":
            return OK, "MPL-2.0 提供 GPL 二级许可，可与 AGPL-3.0 组合。"
        if dep_token in ("LGPL-2.1", "LGPL-3.0"):
            return OK, "%s 代码可升级后纳入 AGPL-3.0 作品。" % dep_token
        if dep_token in ("GPL-2.0", "GPL-3.0"):
            return CONFLICT, "%s 与 AGPL-3.0 的条款不能相互满足，无法单向组合。" % dep_token
        if dep_cat == PROPRIETARY:
            return CONFLICT, "AGPL-3.0 网络交互也触发开源义务，不能与专有代码组合。"

    if parent_cat == PROPRIETARY:
        if dep_cat == PERMISSIVE:
            return OK, "宽松许可证代码可被专有作品使用（保留声明即可）。"
        if dep_token in ("LGPL-2.1", "LGPL-3.0", "MPL-2.0"):
            return WARNING, (
                "%s 属于文件/库级弱 copyleft：满足独立链接、可替换及源码提供义务时可被专有作品使用，"
                "静态合并则不兼容，需要人工确认链接方式。" % dep_token
            )
        if dep_cat == STRONG_COPYLEFT:
            return CONFLICT, "%s 强 copyleft 会使整个专有作品被迫开源，不能集成。" % dep_token
        if dep_cat == PROPRIETARY:
            return WARNING, "双方均为专有许可证，能否一起分发取决于各自商业授权，需要人工确认。"

    # 理论上不会到达
    return WARNING, "无法自动判定，需要人工确认。"


@lru_cache(maxsize=1)
def build_matrix() -> List[Dict[str, object]]:
    """生成完整兼容矩阵（仅包含已知许可证），供 API 与前端展示。"""
    tokens = list(CATEGORIES.keys())
    rows: List[Dict[str, object]] = []
    for parent in tokens:
        cells: List[Dict[str, str]] = []
        for dep in tokens:
            status, reason = compatibility(parent, dep)
            cells.append({"dep": dep, "status": status, "reason": reason})
        rows.append(
            {
                "parent": parent,
                "category": CATEGORIES[parent],
                "cells": cells,
            }
        )
    return rows


def license_info(raw: object) -> Dict[str, object]:
    """规范化许可证并返回富信息字典。"""
    display, token, known = normalize_license(raw)
    category = CATEGORIES.get(token, UNKNOWN)
    return {
        "raw": "" if raw is None else str(raw),
        "display": display,
        "token": token,
        "known": known,
        "category": category,
        "category_label": CATEGORY_LABELS[category],
        "note": CATEGORY_NOTES[category],
    }
