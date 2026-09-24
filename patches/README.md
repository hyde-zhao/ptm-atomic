# 跨仓库配套补丁

本目录存放 **不属于 ptm-atomic**、但与本仓库变更配套的补丁。文件所有者是 ptm-team，
放在这里只是为了让「原子侧 + 执行侧」的同一处改动可以被一起审阅、一起回滚。

## te-op_mapper-bridge_domain_id.patch

**配套提交**：`df98942 feat(atomic): fw_check_bridge_domain 支持可选 --bridge-domain-id`

**文件所有者**：ptm-team — `skills/case-op-execution/scripts/op_mapper.py`
（TE 侧的 case-args → CLI-flag 翻译层，不是 ptm-atomic 的源码）

**改动内容**（纯新增，11 行，无删除）：

1. `ARGS_TO_FLAGS["fw_check_bridge_domain"]` 增加 `"bridge_domain_id": "--bridge-domain-id"`；
2. `_IGNORED_ARGS` 表头增加「反向名单」注释，说明该字段**形似可豁免、实则不可**
   （丢掉会让后置退化为全表查询，无法回答「目标 BD 是否存在」）。

**为什么需要**：BVI 用例的后置普遍写 `fw_check_bridge_domain args={bridge_domain_id: 10}`。
在 `df98942` 之前该 op 只有全表查询、无可传 flag，op_mapper 判 `PARAM_INVALID`，
`exec-20260923-bvi-full` 中 7 条用例因此恒失败。原子侧补上可选参数后，执行侧必须同时登记映射，
否则字段仍会被当未知参数阻塞。

**适用性限制（重要）**：

- 本补丁的行号基于**工作区安装副本**（`case-op-execution/scripts/op_mapper.py`，6597 行，
  `EXPECTED_OP_COUNT = 97`）。
- ptm-team 上游仓库的同名文件是 **8210 行 / `EXPECTED_OP_COUNT = 106`**，且**从未登记
  `fw_check_bridge_domain`**（该 op 在那边整族缺失）。**本补丁对上游文件不适用**，
  不能 `git apply`。
- 上游若需同步，正确做法是补齐 BVI 检查族并相应上调 `EXPECTED_OP_COUNT`，
  而不是套用本补丁。

**应用方式**（仅针对工作区副本）：补丁头里的路径是相对 **skills 根** 的
（`skills/case-op-execution/scripts/op_mapper.py`），工作区实际落在
`ptm-te-liyuanyuan/.claude/` 下。直接指定目标文件最稳妥：

```bash
patch /path/to/.claude/skills/case-op-execution/scripts/op_mapper.py \
      < patches/te-op_mapper-bridge_domain_id.patch
```

该补丁**已经过往返校验**：对改造前的 6597 行文件应用后，与工作区当前文件逐字节一致。
