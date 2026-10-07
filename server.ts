// server.ts - F210 Auth Server (Deno Deploy)
// 部署: deno deploy --project f210-auth --entrypoint server.ts

// ============ 配置（从环境变量读取） ============

interface AuthEntry {
  hwid: string;
  expires_at?: number;       // Unix timestamp, 可选
  note?: string;             // 备注
  enabled: boolean;
}

// HWID 授权表（环境变量 JSON 或硬编码）
function load_hwid_table(): Map<string, AuthEntry> {
  const table = new Map<string, AuthEntry>();

  // 方式1: 环境变量 HWID_TABLE (JSON 字符串)
  const envTable = Deno.env.get("HWID_TABLE");
  if (envTable) {
    try {
      const parsed = JSON.parse(envTable) as Record<string, Omit<AuthEntry, "hwid">>;
      for (const [hwid, entry] of Object.entries(parsed)) {
        table.set(hwid.toUpperCase(), { hwid: hwid.toUpperCase(), ...entry, enabled: entry.enabled ?? true });
      }
    } catch (e) {
      console.error("Failed to parse HWID_TABLE:", e);
    }
  }

  // 方式2: 硬编码（开发/应急用，生产建议全走环境变量）
  // table.set("DE7864D2C1664E39", { hwid: "DE7864D2C1664E39", enabled: true, note: "dev-machine-1" });

  return table;
}

// config_hash 白名单（防止 DLL 被篡改）
const CONFIG_HASH_ALLOWLIST = new Set(
  (Deno.env.get("CONFIG_HASH_ALLOWLIST") ?? "")
    .split(",")
    .map(s => s.trim().toUpperCase())
    .filter(Boolean)
);

// 允许的版本列表
const ALLOWED_VERSIONS = new Set(
  (Deno.env.get("ALLOWED_VERSIONS") ?? "2.1.0")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);

// ============ 响应工具 ============

function json_response(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

function cors_preflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}

// ============ 主服务 ============

const HWID_TABLE = load_hwid_table();

console.log(`[F210 Auth] Loaded ${HWID_TABLE.size} HWID entries`);
console.log(`[F210 Auth] Config hash allowlist: ${CONFIG_HASH_ALLOWLIST.size} entries`);
console.log(`[F210 Auth] Allowed versions: ${[...ALLOWED_VERSIONS].join(", ")}`);

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const method = req.method;

  // CORS preflight
  if (method === "OPTIONS") {
    return cors_preflight();
  }

  // ============ POST /license/check ============
  if (url.pathname === "/license/check" && method === "POST") {
    let body: any = {};
    try {
      body = await req.json();
    } catch {
      return json_response({ error: "invalid json" }, 400);
    }

    const fp = String(body?.fp ?? "").trim().toUpperCase();
    const hwid = String(body?.hwid ?? "").trim().toUpperCase();
    const config_hash = String(body?.config_hash ?? "").trim().toUpperCase();
    const dll_crc = String(body?.dll_crc ?? "").trim().toUpperCase();
    const version = String(body?.version ?? "").trim();
    const device_code = String(body?.device_code ?? "").trim();

    // 基本参数校验
    if (!fp || !hwid) {
      return json_response({ error: "missing fp/hwid", status: "rejected" }, 400);
    }

    // 版本检查（宽松：不在列表里只告警不拒绝）
    const version_ok = !version || ALLOWED_VERSIONS.has(version);
    if (!version_ok) {
      console.log(`[WARN] Unknown version: ${version} from HWID=${hwid}`);
    }

    // ========== 授权判断 ==========

    let authorized = false;
    let auth_method = "none";
    let auth_note = "";

    // 优先级1: HWID 授权表
    const hwid_entry = HWID_TABLE.get(hwid);
    if (hwid_entry && hwid_entry.enabled) {
      // 检查过期
      if (hwid_entry.expires_at && Date.now() > hwid_entry.expires_at) {
        auth_note = "expired";
        console.log(`[DENY] HWID ${hwid} expired at ${hwid_entry.expires_at}`);
      } else {
        authorized = true;
        auth_method = "hwid";
        auth_note = hwid_entry.note ?? "authorized";
        console.log(`[AUTH] HWID ${hwid} authorized via HWID table (${auth_note})`);
      }
    }

    // 优先级2: config_hash 辅助校验（HWID不在表但config_hash对 → 也授权，标记辅助）
    if (!authorized && config_hash && CONFIG_HASH_ALLOWLIST.has(config_hash)) {
      authorized = true;
      auth_method = "config_hash";
      auth_note = "fallback to config hash";
      console.log(`[AUTH] HWID ${hwid} authorized via config_hash ${config_hash}`);
    }

    // 优先级3: 都失败 → 拒绝
    if (!authorized) {
      console.log(`[DENY] HWID ${hwid} rejected (not in table, config_hash=${config_hash || "none"})`);
      return json_response({
        status: "rejected",
        reason: auth_note || "hwid_not_authorized",
        hwid,
        config_hash: config_hash || null,
        suggestion: "Contact admin to authorize this device",
      }, 403);
    }

    // ========== 授权成功 ==========

    // 记录 dll_crc 到日志（用于后续分析）
    if (dll_crc) {
      console.log(`[INFO] Authorized device HWID=${hwid} dll_crc=${dll_crc} version=${version}`);
    }

    return json_response({
      status: "ok",
      authorized: true,
      auth_method,
      note: auth_note,
      fp,
      hwid,
      version: version || null,
      config_hash: config_hash || null,
      dll_crc: dll_crc || null,
      device_code: device_code || null,
      server_time: Date.now(),
    }, 200);
  }

  // ============ GET /admin/pending ============
  if (url.pathname === "/admin/pending" && method === "GET") {
    const auth_header = req.headers.get("Authorization");
    const admin_key = Deno.env.get("ADMIN_KEY");
    if (admin_key && auth_header !== `Bearer ${admin_key}`) {
      return json_response({ error: "unauthorized" }, 401);
    }
    // 这里可以返回待授权列表（需要持久化存储，如 Deno KV）
    return json_response({
      message: "pending list (not implemented, use HWID_TABLE env var)",
      hwid_table_size: HWID_TABLE.size,
      config_hash_allowlist_size: CONFIG_HASH_ALLOWLIST.size,
    });
  }

  // ============ GET /health ============
  if (url.pathname === "/health" && method === "GET") {
    return json_response({
      status: "healthy",
      version: "2.1.0",
      hwid_count: HWID_TABLE.size,
      uptime: Date.now(),
    });
  }

  // ============ 404 ============
  return json_response({
    error: "not found",
    path: url.pathname,
  }, 404);
});