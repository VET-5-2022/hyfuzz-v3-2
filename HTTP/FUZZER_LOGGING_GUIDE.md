# Fuzzer Logging and Statistics Guide

本文档说明了所有fuzzer变体的日志输出和统计数据收集功能。

## 📊 统计数据收集

所有fuzzer都通过 `get_stats()` 方法提供完整的统计数据：

### 基础统计（所有fuzzer）

```python
{
    "iterations": 0,           # 执行的迭代次数
    "crashes": 0,              # 发现的崩溃数量
    "cve_triggers": {},        # 触发的CVE字典
    "seeds_generated": 0,      # 生成的种子数量
    "mutations_performed": 0,  # 执行的变异数量
    "errors": 0,               # 错误数量
    "timeouts": 0              # 超时数量
}
```

### 池化统计（所有池化fuzzer）

```python
{
    "pool_updates": 0,        # 池更新次数
    "update_interval": 10,    # 更新间隔
    "seed_pool_size": 10,     # seed池大小
    "mutation_pool_size": 10  # mutation池大小
}
```

### LLM特定统计

#### LLMSeedFuzzer 和 LLMMutationFuzzer

```python
{
    "llm_successes": 0,       # LLM成功次数
    "llm_failures": 0,        # LLM失败次数
    "llm_stats": {            # LLM客户端统计
        "total_requests": 0,
        "total_successes": 0,
        "total_failures": 0,
        "total_tokens": 0,
        "total_time": 0.0,
        "average_time": 0,
        "errors": 0,
        "model": "qwen3:8b"
    }
}
```

#### LLMFullFuzzer (双池)

```python
{
    "seed_llm_successes": 0,      # Seed池LLM成功
    "seed_llm_failures": 0,       # Seed池LLM失败
    "mutation_llm_successes": 0,  # Mutation池LLM成功
    "mutation_llm_failures": 0,   # Mutation池LLM失败
    "llm_stats": { ... }          # LLM客户端统计
}
```

## 🔍 实时日志输出

### 日志级别

- **INFO**: 重要事件（初始化、池更新完成、进度报告）
- **DEBUG**: 详细信息（每个seed/mutation更新状态）
- **WARNING**: 异常情况（池为空、LLM失败）

### 日志前缀

每个fuzzer使用特定的前缀标识日志来源：

| Fuzzer | 前缀 | 用途 |
|--------|------|------|
| LLMSeedFuzzer | `[LLM-SEED]` | Seed池更新日志 |
| LLMMutationFuzzer | `[LLM-MUTATION]` | Mutation池更新日志 |
| LLMFullFuzzer | `[LLM-FULL]` | 双池更新日志 |
| BoofuzzBaseline | (无前缀) | Baseline日志 |

### 示例日志输出

#### LLMSeedFuzzer 池更新

```
[LLM-SEED] Starting pool update #1 - updating 10 seeds
[LLM-SEED] Updating seed 1/10
[LLM-SEED] ✓ Seed 1 updated successfully
[LLM-SEED] Updating seed 2/10
[LLM-SEED] ✗ Seed 2 update failed, keeping old seed
...
[LLM-SEED] Pool update #1 completed: 8/10 successful (80.0%), total: 8 successes, 2 failures
```

#### LLMMutationFuzzer 池更新

```
[LLM-MUTATION] Starting pool update #1 - updating 10 mutations
[LLM-MUTATION] Updating mutation 1/10 (type: path_traversal)
[LLM-MUTATION] ✓ Mutation 1 updated successfully
[LLM-MUTATION] Updating mutation 2/10 (type: ssrf)
[LLM-MUTATION] ✓ Mutation 2 updated successfully
...
[LLM-MUTATION] Pool update #1 completed: 9/10 successful (90.0%), total: 9 successes, 1 failures
```

#### LLMFullFuzzer 双池更新

```
[LLM-FULL] Starting dual pool update #1 - updating 10 seeds and 10 mutations
[LLM-FULL] Phase 1/2: Updating seed pool...
[LLM-FULL] Updating seed 1/10
[LLM-FULL] ✓ Seed 1 updated
...
[LLM-FULL] Seed pool updated: 8/10 successful (80.0%)
[LLM-FULL] Phase 2/2: Updating mutation pool...
[LLM-FULL] Updating mutation 1/10 (type: path_traversal)
[LLM-FULL] ✓ Mutation 1 updated
...
[LLM-FULL] Mutation pool updated: 9/10 successful (90.0%)
[LLM-FULL] Dual pool update #1 completed: 17/20 total successful (85.0%),
           cumulative: 8 seed successes, 9 mutation successes
```

## 📝 结果存储

### 自动保存

fuzzing结束后，统计数据会自动保存为JSON格式：

```python
# 使用 run_ablation.py 运行时自动保存
python run_ablation.py --variants llm_seed --iterations 100
# 结果保存到: results/llm_seed_YYYYMMDD_HHMMSS.json
```

### 手动保存

```python
from fuzzer.llm_seed_fuzzer import LLMSeedFuzzer
import json

fuzzer = LLMSeedFuzzer()
# ... 运行fuzzing ...
stats = fuzzer.get_stats()

# 保存到文件
with open('results.json', 'w') as f:
    json.dump(stats, f, indent=2)
```

### JSON格式示例

```json
{
  "iterations": 100,
  "crashes": 5,
  "cve_triggers": {
    "CVE-2024-4577": 3,
    "CVE-2024-23897": 2
  },
  "seeds_generated": 100,
  "mutations_performed": 100,
  "errors": 2,
  "timeouts": 1,
  "pool_updates": 10,
  "llm_successes": 85,
  "llm_failures": 15,
  "seed_pool_size": 10,
  "update_interval": 10,
  "llm_stats": {
    "total_requests": 100,
    "total_successes": 85,
    "total_failures": 15,
    "average_time": 1.23,
    "model": "qwen3:8b"
  }
}
```

## 🎯 实时监控

### 查看进度

所有fuzzer在运行时每10次迭代或每30秒输出一次进度：

```
[100/1000] crashes=5, CVEs=7, rate=8.31/s
[200/1000] crashes=12, CVEs=15, rate=8.45/s
```

### 池更新监控

每当池更新发生时（默认每10次迭代），会输出详细的更新信息：

```
[LLM-SEED] Starting pool update #5 - updating 10 seeds
...
[LLM-SEED] Pool update #5 completed: 9/10 successful (90.0%)
```

## 🔧 配置日志级别

### 启用DEBUG日志（查看更多详情）

```python
import logging

# 在脚本开头添加
logging.basicConfig(level=logging.DEBUG)
```

### 只显示关键信息

```python
import logging

# 只显示INFO和以上级别
logging.basicConfig(level=logging.INFO)
```

## 📈 分析统计数据

### 使用测试脚本

运行 `test_fuzzer_logging.py` 查看格式化的统计摘要：

```bash
python test_fuzzer_logging.py
```

输出示例：

```
======================================================================
STATISTICS SUMMARY - llm_seed
======================================================================

📊 Core Metrics:
  Iterations:          100
  Seeds Generated:     100
  Mutations Performed: 100
  Crashes Found:       5
  Errors:              2
  Timeouts:            1

🔄 Pool Metrics:
  Pool Updates:        10
  Update Interval:     10
  Seed Pool Size:      10

🤖 LLM Metrics:
  LLM Successes:       85
  LLM Failures:        15
  Success Rate:        85.0%

  LLM Client Stats:
    Total Requests:    100
    Total Successes:   85
    Total Failures:    15
    Avg Response Time: 1.23s
======================================================================
```

## 💡 最佳实践

### 1. 运行时监控

```bash
# 实时查看日志
python run_ablation.py --variants llm_seed --iterations 100 2>&1 | tee fuzzing.log

# 过滤特定日志
python run_ablation.py ... 2>&1 | grep "\[LLM-SEED\]"
```

### 2. 批量分析结果

```python
import json
from pathlib import Path

# 读取所有结果文件
results = {}
for file in Path('results').glob('*.json'):
    with open(file) as f:
        variant = file.stem.rsplit('_', 2)[0]
        results[variant] = json.load(f)

# 比较不同变体
for variant, stats in results.items():
    print(f"{variant}: {stats['crashes']} crashes, {stats['llm_successes']} LLM successes")
```

### 3. 监控LLM性能

```python
fuzzer = LLMSeedFuzzer()
# ... 运行fuzzing ...
stats = fuzzer.get_stats()

llm_stats = stats['llm_stats']
success_rate = llm_stats['total_successes'] / llm_stats['total_requests'] * 100
print(f"LLM Success Rate: {success_rate:.1f}%")
print(f"Average Response Time: {llm_stats['average_time']:.2f}s")
```

## 🚀 快速开始

### 基本使用

```python
from fuzzer.llm_seed_fuzzer import LLMSeedFuzzer

# 初始化（会输出初始化日志）
fuzzer = LLMSeedFuzzer(
    pool_size=10,
    update_interval=10
)

# 运行（会输出进度和池更新日志）
result = fuzzer.run(iterations=100)

# 获取统计数据
stats = fuzzer.get_stats()
print(f"Crashes: {stats['crashes']}")
print(f"LLM Success Rate: {stats['llm_successes']/(stats['llm_successes']+stats['llm_failures'])*100:.1f}%")
```

### 使用消融研究脚本

```bash
# 运行单个变体
python run_ablation.py --variants llm_seed --iterations 100

# 运行所有变体进行对比
python run_ablation.py --variants boofuzz_baseline llm_seed llm_mutation llm_full --iterations 1000

# 查看结果
ls -lh results/
cat results/llm_seed_*.json
```

## 📚 参考

- `fuzzer/base_fuzzer.py` - 基类实现
- `fuzzer/llm_seed_fuzzer.py` - LLM seed池实现
- `fuzzer/llm_mutation_fuzzer.py` - LLM mutation池实现
- `fuzzer/llm_full_fuzzer.py` - LLM双池实现
- `fuzzer/boofuzz_baseline.py` - Baseline实现
- `test_fuzzer_logging.py` - 测试和演示脚本
- `run_ablation.py` - 完整消融研究脚本
