// 網站可觸發的情境（第 8 節、第 12.0 節）。P2 情境尚未提供輸入資料，按鈕顯示「未啟用」且伺服器拒絕派發。
export const WEB_SCENARIOS = ["daily", "intel-demo", "peer-incident", "early-signal", "php2shell", "nas", "insider-path", "mobile-sdk"] as const;
export const P2_SCENARIOS = new Set<string>(["nas", "insider-path", "mobile-sdk"]);

export function scenarioAvailability(scenario: string): "enabled" | "p2" | "unknown" {
  if (!(WEB_SCENARIOS as readonly string[]).includes(scenario)) return "unknown";
  return P2_SCENARIOS.has(scenario) ? "p2" : "enabled";
}
