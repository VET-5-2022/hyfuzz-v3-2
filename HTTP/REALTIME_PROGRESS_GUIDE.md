# 实时进度监控指南

本指南说明如何在fuzzing运行过程中查看实时进度信息。

## 📊 实时进度输出

所有fuzzer在运行时都会**每10次迭代**（或每30秒）输出一次详细进度：

### 基础进度信息（所有fuzzer）

```
[10/100] crashes=2, CVEs=5 (unique: 3), errors=1, timeouts=0, rate=8.31/s, elapsed=12s
  └─ CVE breakdown: CVE-2024-4577: 3, CVE-2024-23897: 2
```

**包含的信息：**
- `[10/100]`: 当前迭代数 / 总迭代数
- `crashes=2`: 已发现的崩溃数量
- `CVEs=5 (unique: 3)`: CVE触发总数（独立CVE数量）
- `errors=1`: 错误次数
- `timeouts=0`: 超时次数
- `rate=8.31/s`: 执行速率（请求/秒）
- `elapsed=12s`: 已运行时间（秒）

**CVE详细信息：**
- 当触发CVE时，会显示每个CVE的独立计数
- 格式：`CVE-2024-4577: 3, CVE-2024-23897: 2`

## 🔍 各Fuzzer特定信息

### BoofuzzBaseline

```
[20/100] crashes=4, CVEs=8 (unique: 4), errors=2, timeouts=1, rate=8.45/s, elapsed=24s
  └─ CVE breakdown: CVE-2024-4577: 4, CVE-2024-23897: 3, CVE-2025-24813: 1
  └─ [BASELINE] Pools: 10 seeds, 10 mutations, Updates: 2
```

**额外信息：**
- 当前seed池和mutation池的大小
- 已执行的池更新次数

### LLMSeedFuzzer

```
[30/100] crashes=6, CVEs=12 (unique: 5), errors=3, timeouts=0, rate=8.22/s, elapsed=36s
  └─ CVE breakdown: CVE-2024-4577: 5, CVE-2024-23897: 4, CVE-2025-24813: 3
  └─ [LLM-SEED] Pool: 10 seeds, Updates: 3, LLM success rate: 85.0% (34/40)
```

**额外信息：**
- 当前seed池大小
- 已执行的池更新次数
- **LLM成功率**：显示LLM更新的成功率和具体数字

### LLMMutationFuzzer

```
[40/100] crashes=8, CVEs=16 (unique: 6), errors=4, timeouts=1, rate=8.10/s, elapsed=48s
  └─ CVE breakdown: CVE-2024-4577: 6, CVE-2024-23897: 5, CVE-2025-24813: 3, CVE-2024-27316: 2
  └─ [LLM-MUTATION] Pool: 10 mutations, Updates: 4, LLM success rate: 87.5% (42/48)
```

**额外信息：**
- 当前mutation池大小
- 已执行的池更新次数
- **LLM成功率**：显示mutation更新的成功率

### LLMFullFuzzer（双池）

```
[50/100] crashes=10, CVEs=20 (unique: 7), errors=5, timeouts=1, rate=8.05/s, elapsed=60s
  └─ CVE breakdown: CVE-2024-4577: 7, CVE-2024-23897: 6, CVE-2025-24813: 4, CVE-2024-27316: 3
  └─ [LLM-FULL] Pools: 10 seeds, 10 mutations, Updates: 5
     ├─ Seed LLM: 82.0% (41/50), Mutation LLM: 88.0% (44/50)
```

**额外信息：**
- 两个池的大小
- 已执行的池更新次数
- **两个独立的LLM成功率**：
  - Seed池的LLM更新成功率
  - Mutation池的LLM更新成功率

## 🔄 池更新通知

### 单池更新（LLM-SEED / LLM-MUTATION）

当池更新开始时：
```
[LLM-SEED] Starting pool update #1 - updating 10 seeds
```

更新完成时：
```
[LLM-SEED] Pool update #1 completed: 8/10 successful (80.0%), total: 8 successes, 2 failures
```

### 双池更新（LLM-FULL）

更新开始：
```
[LLM-FULL] Starting dual pool update #1 - updating 10 seeds and 10 mutations
```

Phase 1（Seed池）：
```
[LLM-FULL] Phase 1/2: Updating seed pool...
[LLM-FULL] Seed pool updated: 7/10 successful (70.0%)
```

Phase 2（Mutation池）：
```
[LLM-FULL] Phase 2/2: Updating mutation pool...
[LLM-FULL] Mutation pool updated: 9/10 successful (90.0%)
```

更新完成：
```
[LLM-FULL] Dual pool update #1 completed: 16/20 total successful (80.0%),
           cumulative: 7 seed successes, 9 mutation successes
```

## 📝 使用示例

### 运行fuzzing并查看实时进度

```bash
# 运行单个fuzzer
python run_ablation.py --variants llm_seed --iterations 100

# 运行多个fuzzer对比
python run_ablation.py --variants boofuzz_baseline llm_seed llm_full --iterations 500
```

### 保存日志到文件

```bash
# 保存所有输出
python run_ablation.py --variants llm_seed --iterations 100 2>&1 | tee fuzzing.log

# 只查看进度信息（过滤）
python run_ablation.py --variants llm_seed --iterations 100 2>&1 | grep "\[.*\/.*\]"

# 只查看LLM-SEED相关信息
python run_ablation.py --variants llm_seed --iterations 100 2>&1 | grep "LLM-SEED"
```

### 实时监控特定信息

```bash
# 监控crashes和CVE
python run_ablation.py --variants llm_full --iterations 1000 2>&1 | grep -E "crashes=|CVE"

# 监控LLM成功率
python run_ablation.py --variants llm_full --iterations 1000 2>&1 | grep "success rate"

# 监控池更新
python run_ablation.py --variants llm_full --iterations 1000 2>&1 | grep "Pool update"
```

## 🎯 查看演示

运行演示脚本查看模拟的实时进度：

```bash
python demo_realtime_progress.py
```

这将展示所有fuzzer的实时进度输出示例。

## 📈 进度输出频率

### 标准进度（每10次迭代或每30秒）

所有fuzzer都会输出：
- 基础统计（迭代、crashes、CVEs、errors、timeouts、rate、elapsed）
- CVE详细分解
- Fuzzer特定信息（池状态、LLM成功率等）

### 池更新通知（每update_interval次迭代）

默认每10次迭代更新一次池，会显示：
- 更新开始通知
- 更新进度（双池显示Phase 1/2）
- 更新完成统计

### DEBUG级别日志（可选）

启用DEBUG日志可查看每个seed/mutation的更新状态：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

DEBUG输出示例：
```
[LLM-SEED] Updating seed 1/10
[LLM-SEED] ✓ Seed 1 updated successfully
[LLM-SEED] Updating seed 2/10
[LLM-SEED] ✗ Seed 2 update failed, keeping old seed
```

## 💡 实时监控技巧

### 1. 使用 watch 命令监控日志文件

```bash
# 在一个终端运行fuzzing
python run_ablation.py --variants llm_seed --iterations 1000 2>&1 | tee fuzzing.log

# 在另一个终端实时查看进度
watch -n 1 'tail -20 fuzzing.log'
```

### 2. 使用 tail -f 实时跟踪

```bash
# 运行fuzzing
python run_ablation.py --variants llm_full --iterations 1000 2>&1 > fuzzing.log &

# 实时查看日志
tail -f fuzzing.log | grep --line-buffered -E "\[.*\/.*\]|CVE|LLM"
```

### 3. 提取关键指标

```bash
# 提取crashes趋势
grep "crashes=" fuzzing.log | sed 's/.*crashes=\([0-9]*\).*/\1/'

# 提取CVE触发数
grep "CVEs=" fuzzing.log | sed 's/.*CVEs=\([0-9]*\).*/\1/'

# 提取LLM成功率
grep "success rate:" fuzzing.log | sed 's/.*success rate: \([0-9.]*%\).*/\1/'
```

### 4. 生成实时图表（使用 gnuplot）

```bash
# 提取数据
grep "\[.*\/.*\]" fuzzing.log | \
  awk '{print $7, $8}' | \
  sed 's/crashes=//;s/,//' > crashes.dat

# 使用gnuplot绘制
gnuplot -e "plot 'crashes.dat' with lines; pause -1"
```

## 🔧 自定义进度输出

### 修改进度间隔

在 `fuzzer/base_fuzzer.py` 中修改：

```python
progress_interval = 30  # 改为你想要的秒数（例如60秒）
```

或在代码中修改判断条件：

```python
if (i + 1) % 10 == 0 or time_since_last >= progress_interval:
    # 改为每5次迭代：if (i + 1) % 5 == 0
    # 改为每20次迭代：if (i + 1) % 20 == 0
```

### 添加自定义指标

在fuzzer的 `analyze_response` 方法中添加：

```python
def analyze_response(self, payload, response, error):
    result = super().analyze_response(payload, response, error)

    if self._iteration_count % 10 == 0:
        # 添加你的自定义日志
        self.logger.info(f"  └─ Custom metric: {your_metric}")

    return result
```

## 📚 完整示例输出

以下是运行100次迭代的LLM-FULL fuzzer的完整输出示例：

```
2025-12-23 14:30:00 - LLMFullFuzzer - INFO - Starting llm_full fuzzing session with 100 iterations
2025-12-23 14:30:00 - LLMFullFuzzer - INFO - Initializing pools with 10 seeds and mutations
2025-12-23 14:30:00 - LLMFullFuzzer - INFO - Pools initialized: 10 seeds, 10 mutations

2025-12-23 14:30:12 - LLMFullFuzzer - INFO - [10/100] crashes=1, CVEs=3 (unique: 2), errors=0, timeouts=0, rate=0.83/s, elapsed=12s
2025-12-23 14:30:12 - LLMFullFuzzer - INFO -   └─ CVE breakdown: CVE-2024-4577: 2, CVE-2024-23897: 1
2025-12-23 14:30:12 - LLMFullFuzzer - INFO -   └─ [LLM-FULL] Pools: 10 seeds, 10 mutations, Updates: 1
2025-12-23 14:30:12 - LLMFullFuzzer - INFO -      ├─ Seed LLM: 80.0% (8/10), Mutation LLM: 90.0% (9/10)

2025-12-23 14:30:12 - LLMFullFuzzer - INFO - [LLM-FULL] Starting dual pool update #1 - updating 10 seeds and 10 mutations
2025-12-23 14:30:12 - LLMFullFuzzer - INFO - [LLM-FULL] Phase 1/2: Updating seed pool...
2025-12-23 14:30:15 - LLMFullFuzzer - INFO - [LLM-FULL] Seed pool updated: 8/10 successful (80.0%)
2025-12-23 14:30:15 - LLMFullFuzzer - INFO - [LLM-FULL] Phase 2/2: Updating mutation pool...
2025-12-23 14:30:18 - LLMFullFuzzer - INFO - [LLM-FULL] Mutation pool updated: 9/10 successful (90.0%)
2025-12-23 14:30:18 - LLMFullFuzzer - INFO - [LLM-FULL] Dual pool update #1 completed: 17/20 total successful (85.0%), cumulative: 8 seed successes, 9 mutation successes

2025-12-23 14:30:30 - LLMFullFuzzer - INFO - [20/100] crashes=3, CVEs=7 (unique: 4), errors=1, timeouts=0, rate=0.80/s, elapsed=25s
2025-12-23 14:30:30 - LLMFullFuzzer - INFO -   └─ CVE breakdown: CVE-2024-4577: 3, CVE-2024-23897: 2, CVE-2025-24813: 2
2025-12-23 14:30:30 - LLMFullFuzzer - INFO -   └─ [LLM-FULL] Pools: 10 seeds, 10 mutations, Updates: 1
2025-12-23 14:30:30 - LLMFullFuzzer - INFO -      ├─ Seed LLM: 80.0% (8/10), Mutation LLM: 90.0% (9/10)

[... 继续输出直到100次迭代 ...]
```

## 🎓 最佳实践

1. **始终保存日志**：使用 `tee` 命令同时查看和保存
2. **使用过滤器**：用 `grep` 只显示你关心的信息
3. **监控关键指标**：关注crashes、CVE触发、LLM成功率
4. **定期检查池更新**：确保LLM正常工作
5. **对比不同fuzzer**：并行运行多个fuzzer查看差异

## 📞 故障排查

### 没有看到进度输出？

- 检查是否运行了足够的迭代（至少10次）
- 确认日志级别设置为 INFO 或更详细

### LLM成功率为0%？

- 检查LLM服务是否运行（Ollama）
- 查看错误日志了解失败原因

### 池更新通知不出现？

- 确认 update_interval 设置正确
- 运行迭代数应大于 update_interval

---

参考：
- `fuzzer/base_fuzzer.py` - 基础进度日志
- `fuzzer/llm_*.py` - LLM fuzzer特定日志
- `demo_realtime_progress.py` - 进度演示脚本
