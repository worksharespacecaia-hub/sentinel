# SilentAir 入侵亞洲電信設備，攔截以台灣用戶為主的簡訊 2FA 驗證碼
`真實` `已確認`

**結論：無法自動判定：事件沒有可比對的產品、CVE 或控制項，程式沒有比對任何資產，需要人工確認。**

## 事件摘要
Enea 揭露 SilentAir 利用遭入侵的亞洲電信業者內部設備，經 SS7 與 Diameter 送出假的 UpdateLocation，將目標的通話與簡訊轉走，主要目標為台灣行動用戶。部分目標被轉走通訊後，立即有 2FA 碼被攔截。

## 不受影響與需確認
- 需確認：*：人工判斷事件的攻擊手法是否適用於我們的系統；把事件對應到 controls.yaml 的控制項；沒有合適的就建議新增；建議新增控制項：高權限與客戶帳號不得僅以簡訊驗證碼作為第二因素
  - 查：人工判斷事件的攻擊手法是否適用於我們的系統
  - 查：把事件對應到 controls.yaml 的控制項；沒有合適的就建議新增
  - 查：建議新增控制項：高權限與客戶帳號不得僅以簡訊驗證碼作為第二因素

## 處理狀態
需確認

## 來源
- SilentAir Hijacks Asian Telecom Networks to Intercept SMS 2FA Codes and Spy on Taiwanese Users：https://thehackernews.com/2026/11/silentair-hijacks-asian-telecom.html
- 國家級駭客 SilentAir 鎖定台灣用戶 簡訊驗證碼在電信端就被截走：https://cyberq.tw/2026/11/14/silentair-sms-2fa-interception/
