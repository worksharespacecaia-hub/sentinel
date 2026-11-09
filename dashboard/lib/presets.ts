// 攻擊模擬器的預設事件（第 11.2 節 /api/events）：由伺服器依預設產生事件序列，前端不能送任意事件。
// 所有事件 simulated=true 並帶伺服器產生的 simulation_id；IP 使用 RFC 5737 文件保留網段（非真實位址）。
import { randomBytes } from "node:crypto";
import type { RtEvent } from "./rules.ts";

export const PRESETS = ["night-bulk-read", "multi-brand-fraud"] as const;
export type Preset = (typeof PRESETS)[number];

export function newSimulationId(now = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  const ts = `${now.getUTCFullYear()}${p(now.getUTCMonth() + 1)}${p(now.getUTCDate())}${p(now.getUTCHours())}${p(now.getUTCMinutes())}`;
  return `sim-${ts}-${randomBytes(3).toString("hex")}`;
}

/** 當天（Asia/Taipei）凌晨 hh:mm 的 UTC ISO 時間；白天示範也能命中以事件時間判斷的 RT-002。 */
export function taipeiToday(now: Date, hh: number, mm: number, dayOffset = 0): string {
  const tpe = new Date(now.getTime() + 8 * 3600 * 1000);
  const utc = Date.UTC(tpe.getUTCFullYear(), tpe.getUTCMonth(), tpe.getUTCDate() + dayOffset, hh, mm) - 8 * 3600 * 1000;
  return new Date(utc).toISOString();
}

export function buildPreset(preset: Preset, simulationId: string, now = new Date()): RtEvent[] {
  const received = now.toISOString();
  const base = { received_at: received, simulated: true, simulation_id: simulationId };
  const sid = simulationId.slice(4);
  if (preset === "night-bulk-read") {
    // 帳號 dba-alice 基準 200 列／10 分鐘，門檻 > 2000 列；已知 IP 的讀取不計入，新來源 IP 的連續讀取全部計入
    const audit = (n: number, iso: string, ip: string, rows: number): RtEvent => ({
      ...base, id: `sim-${sid}-db-${n}`, source: "db.audit", event_time: iso, asset_id: "order-db-prod", account: "dba-alice",
      data: { table: "orders", rows_read: rows, ip },
    });
    return [
      audit(1, taipeiToday(now, 15, 0, -1), "198.51.100.10", 80),      // 昨天白天：已知 IP 的正常讀取
      audit(2, taipeiToday(now, 2, 10), "198.51.100.10", 120),         // 凌晨但為已知 IP：不計入
      audit(3, taipeiToday(now, 2, 11), "203.0.113.45", 600),          // 新來源 IP 連續讀取
      audit(4, taipeiToday(now, 2, 12), "203.0.113.45", 600),
      audit(5, taipeiToday(now, 2, 13), "203.0.113.45", 600),
      audit(6, taipeiToday(now, 2, 14), "203.0.113.45", 600),          // 累計 2400 > 2000 → 告警
      audit(7, taipeiToday(now, 2, 15), "203.0.113.45", 600),          // 去重期間內：不重複告警
    ];
  }
  const t = (minAgo: number) => new Date(now.getTime() - minAgo * 60 * 1000).toISOString();
  const complaint = (n: number, minAgo: number, brand: string, text: string): RtEvent => ({
    ...base, id: `sim-${sid}-cs-${n}`, source: "support.complaint", event_time: t(minAgo), asset_id: "platform", account: null,
    data: { brand, text },
  });
  return [
    complaint(1, 180, "brand-bloom", "收到簡訊自稱客服，說出我的訂單編號：BL20261108001 要我辦退款"),     // 全形冒號
    complaint(2, 150, "brand-bloom", "App 登入有點慢"),                                                  // 不含訂單資訊
    complaint(3, 120, "brand-hikari", "有人打電話報出我的訂單號碼 HK-20261107-88 要我去 ATM 操作"),      // 無冒號
    complaint(4, 60, "brand-kumo", "scam call quoted my order #KM2026110555 and asked for a refund fee"), // 小寫 order #
    complaint(5, 30, "brand-kumo", "又接到詐騙電話，對方知道訂單編號:KM2026110777"),                        // 同品牌第二件（半形冒號）
  ];
}
