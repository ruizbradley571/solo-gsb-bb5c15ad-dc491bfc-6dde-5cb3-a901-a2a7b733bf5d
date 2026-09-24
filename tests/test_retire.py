"""根包退役预演逻辑的自测（无测试框架依赖）：python -m tests.test_retire"""

from __future__ import annotations

from app import analyzer, retire as retire_mod


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


# 图：
#   r1(GPL-3.0) -> a(MIT) -> x(Proprietary)   （r1 -> x 是硬冲突）
#   r2(MIT)     -> s(Apache-2.0) -> x(Proprietary) （r2 -> x 是需人工确认告警）
#   z(MIT) 为孤立节点（无边；按“没有入边”的定义它本身也是根包）
def _two_root_manifest():
    return {
        "name": "retire-demo",
        "packages": [
            {"name": "r1", "version": "1", "license": "GPL-3.0",
             "dependencies": ["a@1"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["x@1"]},
            {"name": "x", "version": "1", "license": "Proprietary"},
            {"name": "r2", "version": "1", "license": "MIT",
             "dependencies": ["s@1"]},
            {"name": "s", "version": "1", "license": "Apache-2.0",
             "dependencies": ["x@1"]},
            {"name": "z", "version": "1", "license": "MIT"},
        ],
    }


def test_root_detection() -> None:
    result = analyzer.analyze_manifest(_two_root_manifest())
    overview = retire_mod.roots_overview(result)
    root_ids = [r["id"] for r in overview["roots"]]
    # 孤立节点 z 没有入边，按定义也是根包
    _check("roots are r1, r2 and isolated z", root_ids == ["r1@1", "r2@1", "z@1"],
           str(root_ids))
    by_id = {r["id"]: r for r in overview["roots"]}
    _check("r1 reachable set", by_id["r1@1"]["reachable_packages"] == ["a@1", "x@1"],
           str(by_id["r1@1"]["reachable_packages"]))
    _check("r2 reachable set", by_id["r2@1"]["reachable_packages"] == ["s@1", "x@1"],
           str(by_id["r2@1"]["reachable_packages"]))
    _check("isolated root has empty reachable set",
           by_id["z@1"]["reachable_packages"] == [])
    _check("roots overview read only", overview["read_only"] is True)
    _check("summary root count", overview["summary"]["root_packages"] == 3)
    _check("all nodes reachable from some root",
           overview["summary"]["reachable_packages"] == 6)
    _check("no unreachable packages", overview["summary"]["unreachable_packages"] == 0)


def test_baseline_no_retirement() -> None:
    result = analyzer.analyze_manifest(_two_root_manifest())
    out = retire_mod.simulate_retirement(result, [])
    _check("no retired roots", out["summary"]["retired_roots"] == 0)
    _check("no lost packages", out["summary"]["lost_packages"] == 0)
    _check("no shared packages", out["summary"]["shared_packages"] == 0)
    _check("no orphan packages", out["orphan_packages"] == [])
    _check("all conflicts remain",
           out["summary"]["conflicts_remaining"] == out["summary"]["conflicts_before"])
    _check("nothing vanishes", out["summary"]["conflicts_vanished"] == 0)


def test_retire_one_root_lost_shared_conflicts() -> None:
    result = analyzer.analyze_manifest(_two_root_manifest())
    all_keys = {(c["ancestor"], c["node"]): c for c in result["conflicts"]}
    _check("hard conflict r1->x", ("r1@1", "x@1") in all_keys)
    _check("warning r2->x", ("r2@1", "x@1") in all_keys)
    # 约束从每个祖先传播：a->x、s->x 也是告警
    _check("warning a->x", ("a@1", "x@1") in all_keys)
    _check("warning s->x", ("s@1", "x@1") in all_keys)

    out = retire_mod.simulate_retirement(result, ["r1@1"])
    _check("read only flag", out["read_only"] is True)
    _check("retired root listed", [p["id"] for p in out["retired_roots"]] == ["r1@1"])
    _check("remaining roots", out["selection"]["remaining_root_packages"] == ["r2@1", "z@1"])

    # a 仅被 r1 使用 -> 失联；x 被 r2 共用 -> 保留；s 是 r2 独占 -> 保留；z 自身是剩余根
    lost_ids = [p["id"] for p in out["lost_packages"]]
    shared_ids = [p["id"] for p in out["shared_packages"]]
    _check("lost package a", lost_ids == ["a@1"], str(lost_ids))
    _check("shared package x", shared_ids == ["x@1"], str(shared_ids))
    lost_a = out["lost_packages"][0]
    _check("lost package former roots", lost_a["former_root_packages"] == ["r1@1"])
    shared_x = out["shared_packages"][0]
    _check("shared via retired root", shared_x["retired_root_packages"] == ["r1@1"])
    _check("shared via remaining root", shared_x["remaining_root_packages"] == ["r2@1"])

    # 随 r1/a 失联消失的：硬冲突 r1->x 与告警 a->x（共 2 条，含 1 条硬冲突）；
    # r2->x、s->x 两条告警因 x 仍被 r2 共用而保留。
    vanished = out["vanished_conflicts"]
    vanished_keys = {(c["ancestor"], c["node"]) for c in vanished}
    _check("two conflicts vanish",
           vanished_keys == {("r1@1", "x@1"), ("a@1", "x@1")}, str(vanished_keys))
    v = next(c for c in vanished if (c["ancestor"], c["node"]) == ("r1@1", "x@1"))
    _check("vanished keeps original path", v["path"] == ["r1@1", "a@1", "x@1"],
           str(v["path"]))
    _check("path status marks a lost",
           {p["id"]: p["reachable"] for p in v["path_status"]["path"]}
           == {"r1@1": False, "a@1": False, "x@1": True})
    _check("first lost node is retired root",
           v["path_status"]["first_lost_node"] == "r1@1")
    _check("vanish reason mentions retired ancestor", "r1@1" in v["vanish_reason"])
    va = next(c for c in vanished if (c["ancestor"], c["node"]) == ("a@1", "x@1"))
    _check("a->x first lost node a", va["path_status"]["first_lost_node"] == "a@1")
    for c in vanished:
        _check("vanished conflict no review field", "review" not in c)
    remaining_keys = {(c["ancestor"], c["node"]) for c in out["remaining_conflicts"]}
    _check("r2->x warning remains", ("r2@1", "x@1") in remaining_keys)
    _check("s->x warning remains", ("s@1", "x@1") in remaining_keys)
    _check("hard conflict counts",
           out["summary"]["conflicts_vanished_errors"] == 1
           and out["summary"]["conflicts_remaining_errors"] == 0)
    _check("reachable counts",
           out["summary"]["reachable_before"] == 6
           and out["summary"]["reachable_after"] == 4)  # r2,s,x,z


def test_retire_other_root_keeps_shared() -> None:
    result = analyzer.analyze_manifest(_two_root_manifest())
    out = retire_mod.simulate_retirement(result, ["r2@1"])
    lost_ids = [p["id"] for p in out["lost_packages"]]
    shared_ids = [p["id"] for p in out["shared_packages"]]
    _check("s lost", lost_ids == ["s@1"], str(lost_ids))
    _check("x still shared", shared_ids == ["x@1"], str(shared_ids))
    vanished = {(c["ancestor"], c["node"]) for c in out["vanished_conflicts"]}
    _check("warnings r2->x and s->x vanish",
           vanished == {("r2@1", "x@1"), ("s@1", "x@1")}, str(vanished))
    remaining = {(c["ancestor"], c["node"]) for c in out["remaining_conflicts"]}
    _check("hard conflict r1->x remains", ("r1@1", "x@1") in remaining)
    _check("warning a->x remains", ("a@1", "x@1") in remaining)


def test_retire_two_of_three_roots() -> None:
    # 退役 r1、r2（保留孤立根 z）：a/s/x 全部失联，四条冲突都消失，无共用包
    result = analyzer.analyze_manifest(_two_root_manifest())
    out = retire_mod.simulate_retirement(result, ["r1@1", "r2@1"])
    _check("remaining root z", out["selection"]["remaining_root_packages"] == ["z@1"])
    _check("lost a s x",
           [p["id"] for p in out["lost_packages"]] == ["a@1", "s@1", "x@1"],
           str(out["lost_packages"]))
    _check("no shared packages", out["shared_packages"] == [])
    _check("all four conflicts vanished", out["summary"]["conflicts_vanished"] == 4,
           str(out["summary"]))
    _check("one hard conflict vanished",
           out["summary"]["conflicts_vanished_errors"] == 1)
    _check("reachable only z", out["summary"]["reachable_after"] == 1)


def test_errors() -> None:
    result = analyzer.analyze_manifest(_two_root_manifest())

    def expect_error(label, retired, cls):
        try:
            retire_mod.simulate_retirement(result, retired)
        except cls:
            print("ok -", label)
            return
        raise AssertionError(label)

    expect_error("not a list rejected", "r1@1", retire_mod.InvalidSelection)
    expect_error("duplicate selection rejected", ["r1@1", "r1@1"],
                 retire_mod.InvalidSelection)
    expect_error("non-root package rejected", ["a@1"], retire_mod.InvalidSelection)
    expect_error("unknown package rejected", ["nope@9"], retire_mod.InvalidSelection)
    expect_error("all roots rejected", ["r1@1", "r2@1", "z@1"],
                 retire_mod.AllRootsRetired)
    _check("all-roots error status 400",
           retire_mod.AllRootsRetired("x").status == 400)
    _check("invalid selection status 422",
           retire_mod.InvalidSelection("x").status == 422)
    _check("audit not found status 404",
           retire_mod.AuditNotFound("x").status == 404)


def test_single_root_graph() -> None:
    result = analyzer.analyze_manifest(
        {"packages": [
            {"name": "app", "version": "1", "license": "GPL-3.0",
             "dependencies": ["lib@1"]},
            {"name": "lib", "version": "1", "license": "MIT"},
        ]}
    )
    overview = retire_mod.roots_overview(result)
    _check("single root", [r["id"] for r in overview["roots"]] == ["app@1"])
    # 唯一根包退役即退役全部根包 -> 明确错误
    try:
        retire_mod.simulate_retirement(result, ["app@1"])
    except retire_mod.AllRootsRetired:
        print("ok - retiring sole root rejected")
    else:
        raise AssertionError("retiring sole root rejected")


def test_cycle_only_component_is_orphan() -> None:
    # 独立成环 a -> b -> a，无外部根：两者都有入边，故没有根包，整环不可达
    pure_cycle = analyzer.analyze_manifest({
        "packages": [
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT",
             "dependencies": ["a@1"]},
        ]
    })
    overview = retire_mod.roots_overview(pure_cycle)
    _check("no roots in pure cycle", overview["roots"] == [])
    _check("cycle unreachable", overview["summary"]["unreachable_packages"] == 2)
    # 没有根包的图无法退役预演 -> 明确的 422 风格错误，而不是误报“退役全部根包”
    try:
        retire_mod.simulate_retirement(pure_cycle, [])
    except retire_mod.InvalidSelection:
        print("ok - no-root graph rehearsal rejected")
    else:
        raise AssertionError("no-root graph rehearsal rejected")

    # 正常根 c 与一个脱离任何根的纯环并存：环上节点列为 orphan
    result = analyzer.analyze_manifest({
        "packages": [
            {"name": "c", "version": "1", "license": "MIT"},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT",
             "dependencies": ["a@1"]},
        ]
    })
    out = retire_mod.simulate_retirement(result, [])
    _check("detached cycle reported as orphan",
           sorted(p["id"] for p in out["orphan_packages"]) == ["a@1", "b@1"])
    _check("sole root recognized", out["summary"]["root_packages"] == 1)


def test_cycles_safe() -> None:
    # c -> a -> b -> a：根为 c，环上节点经 c 可达
    result = analyzer.analyze_manifest({
        "packages": [
            {"name": "c", "version": "1", "license": "MIT",
             "dependencies": ["a@1"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT",
             "dependencies": ["a@1"]},
        ]
    })
    overview = retire_mod.roots_overview(result)
    _check("cycle graph root c", [r["id"] for r in overview["roots"]] == ["c@1"])
    _check("cycle nodes all reachable", overview["summary"]["reachable_packages"] == 3)
    # 退役唯一根包 = 退役全部根包，应报错而不是在环上死循环
    try:
        retire_mod.simulate_retirement(result, ["c@1"])
    except retire_mod.AllRootsRetired:
        print("ok - sole root in cyclic graph rejected")
    else:
        raise AssertionError("sole root in cyclic graph rejected")

    # 两个根共享一个环：退役其中一个后环仍可达
    result2 = analyzer.analyze_manifest({
        "packages": [
            {"name": "c", "version": "1", "license": "MIT",
             "dependencies": ["a@1"]},
            {"name": "d", "version": "1", "license": "MIT",
             "dependencies": ["b@1"]},
            {"name": "a", "version": "1", "license": "MIT",
             "dependencies": ["b@1"]},
            {"name": "b", "version": "1", "license": "MIT",
             "dependencies": ["a@1"]},
        ]
    })
    overview2 = retire_mod.roots_overview(result2)
    _check("two roots over cycle",
           [r["id"] for r in overview2["roots"]] == ["c@1", "d@1"])
    out = retire_mod.simulate_retirement(result2, ["c@1"])
    _check("cycle kept via other root",
           sorted(p["id"] for p in out["shared_packages"]) == ["a@1", "b@1"],
           str(out["shared_packages"]))
    _check("no lost packages in shared cycle", out["lost_packages"] == [])


def test_source_result_untouched() -> None:
    import copy
    result = analyzer.analyze_manifest(_two_root_manifest())
    snapshot = copy.deepcopy(result)
    retire_mod.simulate_retirement(result, ["r1@1"])
    retire_mod.roots_overview(result)
    _check("original result unchanged", result == snapshot)


def main() -> None:
    test_root_detection()
    test_baseline_no_retirement()
    test_retire_one_root_lost_shared_conflicts()
    test_retire_other_root_keeps_shared()
    test_errors()
    test_single_root_graph()
    test_cycles_safe()
    test_source_result_untouched()
    print("\nall retire tests passed.")


if __name__ == "__main__":
    main()
