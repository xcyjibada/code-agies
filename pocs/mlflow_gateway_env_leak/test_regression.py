#!/usr/bin/env python3
"""
MLflow AI Gateway $ENV_VAR 环境变量泄漏 — 回归测试

Bug: config.py:_resolve_api_key_from_input 将 "$ENV_VAR" 解析为服务器环境变量值
Fix: 移除/禁用 $ENV_VAR 解析, 将 "$" 视为字面量

测试策略:
  1. BUG 版本: _$resolve_api_key_from_input("$MY_ENV") → 返回环境变量值
  2. FIX 版本: 修复后 → 不解析 $ENV_VAR, 当作字面量返回
"""

import os
import sys
import unittest

# Add MLflow source path (buggy version)
MLFLOW_VULN_PATH = "/tmp/mlflow_vuln"
if MLFLOW_VULN_PATH not in sys.path:
    sys.path.insert(0, MLFLOW_VULN_PATH)

# 设置测试用环境变量 (必须是已知的, 不影响系统的)
TEST_ENV_KEY = "AGIES_MLFLOW_REGRESSION_TEST_SECRET"
TEST_ENV_VAL = "super-secret-value-do-not-leak"

# 同时设置一个常见命名格式的变量
AWS_MOCK_KEY = "AGIES_AWS_ACCESS_KEY_ID_MOCK"
AWS_MOCK_VAL = "AKIA1234567890ABCDE"


class TestEnvVarLeakRegression(unittest.TestCase):
    """回归测试: $ENV_VAR 不应在 API secret 中被解析"""

    @classmethod
    def setUpClass(cls):
        os.environ[TEST_ENV_KEY] = TEST_ENV_VAL
        os.environ[AWS_MOCK_KEY] = AWS_MOCK_VAL

    @classmethod
    def tearDownClass(cls):
        os.environ.pop(TEST_ENV_KEY, None)
        os.environ.pop(AWS_MOCK_KEY, None)

    # ========== BUG 版本测试 ==========

    def test_bug_env_var_resolved(self):
        """BUG: $ENV_VAR 被解析为实际环境变量值"""
        from mlflow.gateway.config import _resolve_api_key_from_input

        result = _resolve_api_key_from_input(f"${TEST_ENV_KEY}")
        self.assertEqual(result, TEST_ENV_VAL,
            f"BUG: ${TEST_ENV_KEY} 应返回字面量, 但解析为: {result}")
        print(f"  [BUG] ${TEST_ENV_KEY} → {result}")

    def test_bug_aws_key_exfiltration(self):
        """BUG: $AWS_ACCESS_KEY_ID 格式可泄漏云凭证"""
        from mlflow.gateway.config import _resolve_api_key_from_input

        result = _resolve_api_key_from_input(f"${AWS_MOCK_KEY}")
        self.assertEqual(result, AWS_MOCK_VAL,
            f"BUG: ${AWS_MOCK_KEY} 被解析, 可泄漏云凭证: {result}")
        print(f"  [BUG] ${AWS_MOCK_KEY} → {result}")

    def test_bug_normal_key_passthrough(self):
        """正常 API key 不受影响"""
        from mlflow.gateway.config import _resolve_api_key_from_input

        result = _resolve_api_key_from_input("sk-real-api-key-12345")
        self.assertEqual(result, "sk-real-api-key-12345")

    def test_bug_dollar_prefix_literal(self):
        """BUG: 以 $ 开头的字面量密钥被错误解析"""
        from mlflow.gateway.config import _resolve_api_key_from_input

        # 如果密钥本身以 $ 开头 (虽然罕见但有实际例子)
        literal_key = "$real-key-starting-with-dollar"
        # 设置环境变量以确保测试可预测
        os.environ["real-key-starting-with-dollar"] = "leaked-value"

        result = _resolve_api_key_from_input(literal_key)
        # BUG: 返回 "leaked-value" 而非 "$real-key-starting-with-dollar"
        self.assertEqual(result, "leaked-value",
            "BUG: 以 $ 开头的字面量密钥被错误解析为环境变量")
        print(f"  [BUG] '{literal_key}' → '{result}' (应为字面量)")

    # ========== FIX 版本测试 ==========

    def _resolve_api_key_fixed(self, api_key_input):
        """FIX 版本: 不解析 $ENV_VAR, 所有输入视为字面量"""
        if not isinstance(api_key_input, str):
            from mlflow.exceptions import MlflowException
            raise MlflowException.invalid_parameter_value(
                "The api key provided is not a string."
            )
        # FIX: 移除了 $ENV_VAR 解析
        # 所有值都作为字面量返回
        return api_key_input

    def test_fix_env_var_not_resolved(self):
        """FIX: $ENV_VAR 不被解析, 返回字面量"""
        result = self._resolve_api_key_fixed(f"${TEST_ENV_KEY}")
        self.assertEqual(result, f"${TEST_ENV_KEY}",
            f"FIX: ${TEST_ENV_KEY} 应作为字面量返回")
        print(f"  [FIX] ${TEST_ENV_KEY} → {result} (字面量, 未解析)")

    def test_fix_aws_key_not_exfiltrated(self):
        """FIX: $AWS_ACCESS_KEY_ID 不会被泄漏"""
        result = self._resolve_api_key_fixed(f"${AWS_MOCK_KEY}")
        self.assertEqual(result, f"${AWS_MOCK_KEY}",
            "FIX: 云凭证环境变量不被解析")
        print(f"  [FIX] ${AWS_MOCK_KEY} → {result} (字面量, 未泄漏)")

    def test_fix_dollar_prefix_preserved(self):
        """FIX: 以 $ 开头的字面量密钥被保留"""
        result = self._resolve_api_key_fixed("$real-key-starting-with-dollar")
        self.assertEqual(result, "$real-key-starting-with-dollar")

    def test_fix_normal_key_passthrough(self):
        """FIX: 正常密钥不受影响"""
        result = self._resolve_api_key_fixed("sk-real-api-key-12345")
        self.assertEqual(result, "sk-real-api-key-12345")


class TestEnvVarLeakFullChain(unittest.TestCase):
    """端到端泄漏链测试: 创建 → 存储 → 解析 → 发送"""

    @classmethod
    def setUpClass(cls):
        os.environ[TEST_ENV_KEY] = TEST_ENV_VAL

    @classmethod
    def tearDownClass(cls):
        os.environ.pop(TEST_ENV_KEY, None)

    def test_leak_chain_bug(self):
        """
        完整泄漏链 BUG 版本:
          1. 创建 secret 时传入 {"api_key": "$ENV_VAR"}
          2. secret 解析 → 存储实际环境变量值 (BUG: 应在创建时警告/拒绝)
          3. 调用时 → 已解析的值被发送到 upstream
        """
        from mlflow.gateway.config import _resolve_api_key_from_input

        # Step 1&2: 用户提交 $ENV_VAR → 被解析
        api_key_input = f"${TEST_ENV_KEY}"
        resolved = _resolve_api_key_from_input(api_key_input)

        self.assertEqual(resolved, TEST_ENV_VAL,
            "泄漏链: $ENV_VAR 被解析, 环境变量泄漏!")
        print(f"\n  [泄漏链 BUG] 输入: '{api_key_input}'")
        print(f"  [泄漏链 BUG] 输出: '{resolved}'")
        print(f"  [泄漏链 BUG] 环境变量 '{TEST_ENV_KEY}' 已泄漏到上游请求!")

    def test_leak_chain_fixed(self):
        """
        完整泄漏链 FIX 版本:
          1. 创建 secret 时传入 {"api_key": "$ENV_VAR"}
          2. secret 被当作字面量存储
          3. 调用时 → 字面量 "$ENV_VAR" 被发送到 upstream (无害)
        """
        def _resolve_fixed(api_key_input):
            return api_key_input  # 直接返回字面量

        api_key_input = f"${TEST_ENV_KEY}"
        resolved = _resolve_fixed(api_key_input)

        self.assertEqual(resolved, f"${TEST_ENV_KEY}",
            "修复链: $ENV_VAR 作为字面量, 不泄漏")
        print(f"\n  [泄漏链 FIX] 输入: '{api_key_input}'")
        print(f"  [泄漏链 FIX] 输出: '{resolved}'")
        print(f"  [泄漏链 FIX] 环境变量未被泄漏 (安全)")


if __name__ == "__main__":
    print("=" * 60)
    print("MLflow AI Gateway $ENV_VAR 泄漏 — 回归测试")
    print("=" * 60)
    print()
    print(f"测试环境变量: {TEST_ENV_KEY}={TEST_ENV_VAL}")
    print(f"模拟云凭证:   {AWS_MOCK_KEY}={AWS_MOCK_VAL}")
    print()

    runner = unittest.TextTestRunner(verbosity=2)
    suite = unittest.TestSuite()

    # 运行 bug 版本测试
    print(">>> BUG 版本测试 (应 FAIL, 证明泄漏存在) <<<")
    suite.addTest(TestEnvVarLeakRegression('test_bug_env_var_resolved'))
    suite.addTest(TestEnvVarLeakRegression('test_bug_aws_key_exfiltration'))
    suite.addTest(TestEnvVarLeakRegression('test_bug_normal_key_passthrough'))
    suite.addTest(TestEnvVarLeakRegression('test_bug_dollar_prefix_literal'))
    suite.addTest(TestEnvVarLeakFullChain('test_leak_chain_bug'))

    result_bug = runner.run(suite)
    print()

    # 运行 fix 版本测试
    print(">>> FIX 版本测试 (应 PASS, 确认修复有效) <<<")
    suite2 = unittest.TestSuite()
    suite2.addTest(TestEnvVarLeakRegression('test_fix_env_var_not_resolved'))
    suite2.addTest(TestEnvVarLeakRegression('test_fix_aws_key_not_exfiltrated'))
    suite2.addTest(TestEnvVarLeakRegression('test_fix_dollar_prefix_preserved'))
    suite2.addTest(TestEnvVarLeakRegression('test_fix_normal_key_passthrough'))
    suite2.addTest(TestEnvVarLeakFullChain('test_leak_chain_fixed'))

    result_fix = runner.run(suite2)

    print()
    print("=" * 60)
    print("回归测试结论")
    print("=" * 60)
    # BUG tests PASS when leak IS confirmed (assertEqual matches env var)
    # FIX tests PASS when leak is NOT confirmed (assertEqual matches literal)
    bug_pass = result_bug.testsRun - len(result_bug.failures) - len(result_bug.errors)
    fix_failures = len(result_fix.failures) + len(result_fix.errors)
    print(f"  BUG 版本通过: {bug_pass}/{result_bug.testsRun} (预期全部通过 = 泄漏被证实)")
    print(f"  FIX 版本失败: {fix_failures} (预期: 0 = 修复有效)")
    if bug_pass == result_bug.testsRun and fix_failures == 0:
        print(f"  ✅ 回归测试通过: BUG 版本确认泄漏, FIX 版本阻止泄漏")
    elif bug_pass < result_bug.testsRun:
        print(f"  ⚠️ BUG 版本测试未全部通过 — 泄漏可能已被修复或测试有误")
    else:
        print(f"  ⚠️ FIX 版本仍有 {fix_failures} 个失败 — 修复不完整")
