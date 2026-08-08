<div align="center">

# Canton Proof-of-Solvency(偿付能力证明)

**公开承诺,密码学证明,人人可验。**

面向 [Canton Network](https://www.canton.network/) 上交易所与托管类应用的
隐私保护型偿付能力证明基础设施。

[![CI](https://github.com/Rocky-exchange/canton-proof-of-solvency/actions/workflows/ci.yml/badge.svg)](https://github.com/Rocky-exchange/canton-proof-of-solvency/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](rust/solvency-merkle/Cargo.toml)
[![Spec](https://img.shields.io/badge/wire_format-v1-informational.svg)](SPEC.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[English](README.md) | 简体中文

</div>

---

## 📖 项目简介

Canton 的隐私模型对机构是最大优势,对公共信任却是最难的问题:**不存在一个任何人
都能重算某个平台账目的公开账本。** Canton 上的交易所、托管方和资产平台,一直缺少
一种不泄露私有数据就能证明"托管资产 ≥ 用户负债"的标准方法。

本项目补上这块缺口:平台每日发布一份覆盖全部用户余额的密码学承诺;每位用户
**完全在自己的浏览器里**验证自己的余额被计入公开总额。原始数据永不离开平台的
participant 节点,公众看到的是承诺、证明与总额——与 Canton 本身相同的信任形态。

## ✨ 核心特性

- **Merkle 求和树承诺** —— 每个节点都携带逐资产总额,树根即公开负债数字;漏记
  用户、缩减余额、虚报总额,都会破坏某个用户的证明。
- **用户自助验证** —— 基于 WebCrypto 在浏览器本地完成,数学过程不经过任何
  服务器,无须信任平台。
- **跨实现黄金测试向量** —— Rust 生产端与 TypeScript 验证端断言完全相同的
  字节级向量([SPEC.md](SPEC.md) §6),两套实现不可能悄悄分叉。
- **诚实的边界处理** —— 负权益钳零并作为坏账披露(绝不允许抵消其他用户的
  余额);自营账户剔除并披露;奇数节点提升而非复制。
- **精确算术** —— 全链路 18 位定点小数,与 `NUMERIC(38,18)` 账本无损对应;
  所有加法均做溢出检查。
- **生产环境验证** —— 支撑 [Rocky](https://rocky.exchange)(Canton 原生
  衍生品与现货交易所)的每日偿付报告与公开 Transparency 页面。

## 🏗️ 架构

```text
 ┌───────────────────────── 平台侧(私有)──────────────────────────┐
 │                                                                  │
 │  账本快照 ──► 逐用户权益 ──► 叶子 ──► Merkle 求和树              │
 │  (单事务一致读,  (负值钳零、    (HMAC     (每个节点              │
 │   钉在事件流      剔除自营户)    派生盐)    校验求和)     │       │
 │   高水位)                                                │       │
 └──────────────────────────────────────────────────────────┼───────┘
                                                            ▼
                                    公开报告:根哈希 + 逐资产总额
                                    + 标记价格 + 披露项
                                                            │
 ┌───────────────────────── 用户侧(浏览器)─────────────────┼───────┐
 │                                                          ▼       │
 │  证明 = 叶子原像(盐、余额)+ 兄弟路径                           │
 │  ① 重算叶子哈希   ② 折叠路径   ③ 同时比对根哈希与总额           │
 └──────────────────────────────────────────────────────────────────┘
```

| 组件 | 路径 | 说明 |
|---|---|---|
| `canton-solvency-merkle` | [`rust/solvency-merkle`](rust/solvency-merkle) | 生产端承诺核心(Rust) |
| `canton-solvency-verifier` | [`ts/verifier`](ts/verifier) | 浏览器验证端(TypeScript,WebCrypto + BigInt) |
| 线格式规范 | [`SPEC.md`](SPEC.md) | 字节级格式 v1 + 黄金测试向量 |
| 示例 | [`examples/csv_report.rs`](rust/solvency-merkle/examples/csv_report.rs) | CSV → 树根、总额、已验证证明 |

## 🚀 快速开始

**环境要求:** Rust ≥ 1.75(生产端)· Node.js ≥ 18(验证端)。

Rust —— 从一份 CSV 构建承诺并端到端验证证明:

```bash
cd rust/solvency-merkle
cargo test                                          # 含 SPEC 黄金向量
cargo run --example csv_report -- balances.csv my-master-salt
```

TypeScript —— 对同一组黄金向量运行验证端:

```bash
cd ts/verifier
npm install && npm test
```

在网页中嵌入验证:

```ts
import { leafHashHex, combineNodes, sumBalances } from "canton-solvency-verifier";

// ① 用证明中披露的盐与余额重算用户叶子哈希
const leafHash = await leafHashHex(proof.leaf.salt, proof.leaf.user_id, proof.leaf.balances);
// ② 用 combineNodes(...) 沿兄弟路径逐层折叠
// ③ 将最终哈希与逐资产总额同时与公开树根比对
```

## 🔌 生产端接入

1. **一致性快照** —— 单事务读取;记录账本高水位,把快照钉在事件历史的确定位置。
2. **计算权益** —— 逐用户逐资产;负值钳零并记录坏账;剔除自营账户但披露户数与
   总额。
3. **构建承诺** —— 按稳定用户顺序生成叶子(`leaf_salt` + `leaf_node`),再
   `SumTree::build`。
4. **发布** —— 根哈希、根总额(即负债总额)、标记价格、披露项;向每位用户提供
   其叶子原像与 `tree.prove(i)`。

生产端义务的完整规范见 [SPEC.md](SPEC.md) §7。

## 🔒 安全模型

**验证通过意味着什么:** 你的余额被按向你披露的数值如实承诺;该承诺聚合进公开
树根;树根总额等于全部已承诺叶子之和。

**它本身不证明什么:** 不能证明*每一位*真实用户都在树中(依赖用户抽查——因此
参考部署把验证做成页面上的一次点击),也不能证明资产侧的诚实(托管核验是
路线图的下一项)。频率也有边界:每日快照只承诺每日状态,不覆盖日内。

发现安全漏洞?请私下报告 —— 见 [SECURITY.md](SECURITY.md)。

## 📦 版本与兼容性

线格式版本由烙进每个哈希的域字符串标识(`rocky-solvency-leaf-v1`、
`rocky-solvency-node-v1`)。**任何打破 [SPEC.md](SPEC.md) §6 黄金向量的改动
都是新的格式版本**,必须换用新的域字符串发布——绝不允许静默变更。crate 与
npm 包遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## 🗺️ 路线图

- [ ] 托管资产侧核验:负债承诺与 Canton party 持仓在同一份覆盖率报告中配对
- [ ] 报告根上链锚定(防篡改历史)
- [ ] 独立审计 CLI(批量验证用户证明)
- [ ] 形成两个独立部署后,将线格式规范上升为 CIP

## 🤝 参与贡献

欢迎贡献 —— 开发环境、测试要求与"黄金向量规则"见
[CONTRIBUTING.md](CONTRIBUTING.md)。本项目遵循
[贡献者公约](CODE_OF_CONDUCT.md),参与即表示你同意遵守。

## 👥 谁在使用

| 使用方 | 场景 |
|---|---|
| [Rocky](https://rocky.exchange) | 每日偿付报告 + 公开 Transparency 页面,用户浏览器内自助验证 |

如果你的项目也在使用,欢迎提 PR 把自己加进来。

## 📄 许可证

[Apache-2.0](LICENSE) © Rocky Exchange contributors.
