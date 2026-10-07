// server.ts - F210 Auth Server (Deno Deploy + KV 审批流)
// 部署: deno deploy --project f210-auth --entrypoint server.ts

// ============ 配置（从环境变量读取） ============

// 【重要】填入你的 CRC32 哈希值（大写，逗号分隔）
// 例如: "237BCABA,A1B2C3D4"
const CONFIG_HASH_ALLOWLIST = new Set(
  (Deno.env.get("CONFIG_HASH_ALLOWLIST") ?? "66C5B52C")
    .split(",")
    .map(s => s.trim().toUpperCase())
    .filter(Boolean)
);

// 允许的 DLL CRC32 白名单（防 DLL 被篡改）
const DLL_CRC_ALLOWLIST = new Set(
  (Deno.env.get("DLL_CRC_ALLOWLIST") ?? "66C5B52C")
    .split(",")
    .map(s => s.trim().toUpperCase())
    .filter(Boolean)
);

// 管理员密钥（用于审批接口）
const ADMIN_KEY = Deno.env.get("ADMIN_KEY") ?? "zengzong323232";

// 允许的版本
const ALLOWED_VERSIONS = new Set(
  (Deno.env.get("ALLOWED_VERSIONS") ?? "2.1.0")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
);

// 初始化 Deno KV 数据库
const kv = await Deno.openKv();

// ============ KV 工具函数 ============

interface AuthEntry {
  hwid: string;
  expires_at?: number;
  note?: string;
  approved_at: number;
  version?: string;
  device_code?: string;
  dll_crc?: string;
}

interface PendingEntry {
  hwid: string;
  fp: string;
  config_hash?: string;
  dll_crc?: string;
  version?: string;
  device_code?: string;
  first_seen_at: number;
  last_seen_at: number;
  request_count: number;
}

async function get_approved(hwid: string): Promise<AuthEntry | null> {
  const res = await kv.get<AuthEntry>(["approved", hwid.toUpperCase()]);
  return res.value;
}

async function set_approved(entry: AuthEntry): Promise<void> {
  // 如果设置了过期天数，计算毫秒数传给 KV 的 expireIn
  const expireIn = entry.expires_at ? entry.expires_at - Date.now() : undefined;
  await kv.set(["approved", entry.hwid.toUpperCase()], entry, { expireIn });
}

async function delete_approved(hwid: string): Promise<void> {
  await kv.delete(["approved", hwid.toUpperCase()]);
}

async function get_pending(hwid: string): Promise<PendingEntry | null> {
  const res = await kv.get<PendingEntry>(["pending", hwid.toUpperCase()]);
  return res.value;
}

async function set_pending(entry: PendingEntry): Promise<void> {
  await kv.set(["pending", entry.hwid.toUpperCase()], entry);
}

async function delete_pending(hwid: string): Promise<void> {
  await kv.delete(["pending", hwid.toUpperCase()]);
}

async function list_pending(): Promise<PendingEntry[]> {
  const entries = [];
  for await (const entry of kv.list<PendingEntry>({ prefix: ["pending"] })) {
    entries.push(entry.value);
  }
  return entries;
}

async function list_approved(): Promise<AuthEntry[]> {
  const entries = [];
  for await (const entry of kv.list<AuthEntry>({ prefix: ["approved"] })) {
    entries.push(entry.value);
  }
  return entries;
}

// ============ 响应工具 ============

function json_response(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

function cors_preflight(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

// 管理员权限校验中间件
function require_admin(req: Request): boolean {
  const auth = req.headers.get("Authorization");
  return auth === `Bearer ${ADMIN_KEY}`;
}

// ============ 主服务 ============

console.log(`[F210 Auth] Server started`);
console.log(`[F210 Auth] Config hash allowlist: ${CONFIG_HASH_ALLOWLIST.size} entries`);
console.log(`[F210 Auth] DLL CRC allowlist: ${DLL_CRC_ALLOWLIST.size} entries`);
console.log(`[F210 Auth] Admin key configured: ${!!Deno.env.get("ADMIN_KEY")}`);

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const method = req.method;

  if (method === "OPTIONS") return cors_preflight();

  // ============ POST /license/check ============
  if (url.pathname === "/license/check" && method === "POST") {
    let body: any = {};
    try { body = await req.json(); } 
    catch { return json_response({ error: "invalid json" }, 400); }

    const fp = String(body?.fp ?? "").trim().toUpperCase();
    const hwid = String(body?.hwid ?? "").trim().toUpperCase();
    const config_hash = String(body?.config_hash ?? "").trim().toUpperCase();
    const dll_crc = String(body?.dll_crc ?? "").trim().toUpperCase();
    const version = String(body?.version ?? "").trim();

    if (!fp || !hwid) {
      return json_response({ error: "missing fp/hwid", status: "rejected" }, 400);
    }

    // 1. 检查是否在已审批白名单
    const approved = await get_approved(hwid);
    if (approved) {
      // 严格模式：检查 DLL CRC 是否被篡改
      if (dll_crc && DLL_CRC_ALLOWLIST.size > 0 && !DLL_CRC_ALLOWLIST.has(dll_crc)) {
        console.log(`[DENY] HWID ${hwid} DLL CRC mismatch: ${dll_crc}`);
        return json_response({ status: "rejected", reason: "dll_tampered" }, 403);
      }
      
      // 检查过期
      if (approved.expires_at && Date.now() > approved.expires_at) {
        await delete_approved(hwid);
        console.log(`[DENY] HWID ${hwid} expired`);
        return json_response({ status: "rejected", reason: "expired" }, 403);
      }

      console.log(`[AUTH] HWID ${hwid} authorized via Whitelist`);
      return json_response({
        status: "ok",
        authorized: true,
        auth_method: "whitelist",
        fp,
        hwid,
        version: version || null,
        server_time: Date.now(),
      });
    }

    // 2. 检查 Config Hash 辅助放行（免审批信任）
    if (config_hash && CONFIG_HASH_ALLOWLIST.has(config_hash)) {
      console.log(`[AUTH] HWID ${hwid} authorized via Config Hash fallback`);
      return json_response({
        status: "ok",
        authorized: true,
        auth_method: "config_hash",
        fp,
        hwid,
        server_time: Date.now(),
      });
    }

    // 3. 未授权：记入 Pending 表等待审批
    const existing_pending = await get_pending(hwid);
    const pending_entry: PendingEntry = {
      hwid,
      fp,
      config_hash,
      dll_crc,
      version,
      device_code: String(body?.device_code ?? ""),
      first_seen_at: existing_pending?.first_seen_at ?? Date.now(),
      last_seen_at: Date.now(),
      request_count: (existing_pending?.request_count ?? 0) + 1,
    };
    await set_pending(pending_entry);

    console.log(`[PENDING] New/Updated pending device HWID=${hwid} config_hash=${config_hash}`);
    return json_response({
      status: "pending",
      authorized: false,
      reason: "awaiting_admin_approval",
      hwid,
    }, 202); // 202 Accepted
  }

  // ============ 管理员接口（需 ADMIN_KEY） ============
  if (url.pathname.startsWith("/admin/")) {
    if (!require_admin(req)) {
      return json_response({ error: "unauthorized" }, 401);
    }

    // GET /admin/pending
    if (url.pathname === "/admin/pending" && method === "GET") {
      const list = await list_pending();
      return json_response({ count: list.length, pending: list });
    }

    // POST /admin/approve
    if (url.pathname === "/admin/approve" && method === "POST") {
      const body = await req.json();
      const hwid = String(body?.hwid ?? "").trim().toUpperCase();
      if (!hwid) return json_response({ error: "missing hwid" }, 400);

      const expires_in_days = Number(body?.expires_in_days ?? 0);
      const expires_at = expires_in_days > 0 ? Date.now() + expires_in_days * 24 * 60 * 60 * 1000 : undefined;

      const pending = await get_pending(hwid);
      
      const entry: AuthEntry = {
        hwid,
        expires_at,
        note: String(body?.note ?? pending?.fp ?? "manual_approve"),
        approved_at: Date.now(),
        version: pending?.version,
        device_code: pending?.device_code,
        dll_crc: pending?.dll_crc,
      };

      await set_approved(entry);
      await delete_pending(hwid); // 从待审移出

      console.log(`[ADMIN] Approved HWID ${hwid}`);
      return json_response({ success: true, action: "approved", entry });
    }

    // POST /admin/revoke
    if (url.pathname === "/admin/revoke" && method === "POST") {
      const body = await req.json();
      const hwid = String(body?.hwid ?? "").trim().toUpperCase();
      if (!hwid) return json_response({ error: "missing hwid" }, 400);
      
      await delete_approved(hwid);
      await delete_pending(hwid);
      
      console.log(`[ADMIN] Revoked HWID ${hwid}`);
      return json_response({ success: true, action: "revoked", hwid });
    }
    
    // GET /admin/list
    if (url.pathname === "/admin/list" && method === "GET") {
      const list = await list_approved();
      return json_response({ count: list.length, approved: list });
    }
  }

  // ============ GET /health ============
  if (url.pathname === "/health" && method === "GET") {
    return json_response({
      status: "healthy",
      version: "2.1.0",
      admin_key_configured: !!Deno.env.get("ADMIN_KEY"),
      approved_count: (await list_approved()).length,
      pending_count: (await list_pending()).length,
    });
  }

  return json_response({ error: "not found", path: url.pathname }, 404);
});