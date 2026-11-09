import type { NextConfig } from "next";

const config: NextConfig = {
  // public/data 由 A5 發布；伺服器端頁面以 fs 讀取，需打包進函式
  outputFileTracingIncludes: { "/**": ["./public/data/**/*"] },
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Robots-Tag", value: "noindex, nofollow" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
};

export default config;
