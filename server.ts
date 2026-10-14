/**
* server.ts v2.7.1
* F210 Auth Server - + X-Sign HMAC-SHA256 签名校验
*
* 变更日志:
* - v2.7.1: 修复 HMAC 密钥长度不一致（填充到32字节对齐 bridge 端）；DLL CRC 白名单改为小写
* - v2.7.0: 新增 X-Sign 请求头 HMAC-SHA256 校验
* - config_hash / dll_crc 白名单强制校验
* - 签名失败返回 403 rejected
*/
const ADMIN_KEY = Deno.env.get("ADMIN_KEY") || "zengzong323232";
// ★ 签名密钥：必须和 bridge 端硬编码的密钥一致！
const SIGN_SECRET = Deno.env.get("SIGN_SECRET") || "f210_sign_key_2026";
const KV = await Deno.openKv();

// ★ 填入你允许的 config_hash 白名单（bridge 端算出的 HMAC 值）
const VALID_CONFIG_HASHES: string[] = [
  "98abc6fa51cae04e02a829a9deb90a0ca8d91e0e586fba336442363aae17fe19",
];

// ★ 填入你允许的 DLL SHA256 白名单（全小写，和 server 端 .toLowerCase() 对齐）
const VALID_DLL_CRCS: string[] = [
  "f1cd8b98e865e07e23d729c4c9c0f9ff0031a6c1bae108cbbdb4d810c47f7f8a",
  // 之前测试用的旧值: "11fb8c15e3a3452b007f677e8b73b6c3459b5d501a21033ff209ec768479cde6",
];

// ============ HMAC-SHA256 签名校验 ============
async function verify_x_sign(
  hwid: string,
  cpu_fp: string,
  board_fp: string,
  config_hash: string,
  dll_crc: string,
  timestamp: string,
  client_sign: string
): Promise<boolean> {
  // ★ 拼接格式和 bridge 端完全一致
  const message = `${hwid}|${cpu_fp}|${board_fp}|${config_hash}|${dll_crc}|${timestamp}`;
  const encoder = new TextEncoder();

  // ★ 密钥填充到 32 字节（和 bridge 端 BYTE sign_key[32] 循环逻辑对齐）
  let keyBytes = encoder.encode(SIGN_SECRET);
  if (keyBytes.length < 32) {
    const padded = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      padded[i] = keyBytes[i % keyBytes.length];
    }
    keyBytes = padded;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  const sig_hex = Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  // timing-safe 比较
  if (sig_hex.length !== client_sign.length) return false;
  let diff = 0;
  for (let i = 0; i < sig_hex.length; i++) {
    diff |= sig_hex.charCodeAt(i) ^ client_sign.charCodeAt(i);
  }
  return diff === 0;
}

function now_str(): string {
  const d = new Date(Date.now() + 8 * 60 * 60 * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function gen_device_code(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function cors_headers(): Headers {
  const h = new Headers();
  h.set("Content-Type", "application/json");
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Sign");
  return h;
}

interface DeviceRecord {
  fp: string;
  device_code: string | null;
  hwid: string;
  status: "pending" | "active" | "hw_changed" | "revoked" | "banned" | "expired";
  created_at: string;
  last_seen_at: string;
  last_request: string;
  activated_at: string | null;
  expires_at: string | null;
  allowed_versions: string[];
  current_version: string | null;
  hwid_history: string[];
  transfer_count: number;
  max_transfers: number;
  note: string;
  contact: string;
  order_id: string | null;
  purchase_date: string | null;
  license_type: string | null;
  total_requests: number;
  last_ip: string | null;
  board: string;
  cpu: string;
  cpu_fp: string;
  board_fp: string;
  config_hash: string;
  dll_crc: string;
  config_hash_valid?: boolean;
  dll_crc_valid?: boolean;
  hw_change_count: number;
  hw_change_reset_at: string;
}

function create_empty_device(fp: string, hwid: string): DeviceRecord {
  const now = now_str();
  return {
    fp, device_code: null, hwid,
    status: "pending",
    created_at: now, last_seen_at: now, last_request: now,
    activated_at: null, expires_at: null,
    allowed_versions: [], current_version: null,
    hwid_history: [hwid], transfer_count: 0, max_transfers: 3,
    note: "", contact: "",
    order_id: null, purchase_date: null, license_type: null,
    total_requests: 0, last_ip: null,
    board: "", cpu: "",
    cpu_fp: "", board_fp: "",
    config_hash: "", dll_crc: "",
    hw_change_count: 0,
    hw_change_reset_at: now,
  };
}

function check_admin_auth(req: Request): boolean {
  const auth = req.headers.get("Authorization");
  if (!auth) return false;
  return auth === `Bearer ${ADMIN_KEY}`;
}

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  if (method === "OPTIONS") {
    return new Response(null, { headers: cors_headers() });
  }

  // ============ /license/check ============
  if (path === "/license/check" && method === "POST") {
    try {
      const body = await req.json();
      const fp = body.fp || body.hwid || "";
      const hwid = body.hwid || fp;
      const board = body.board || "";
      const cpu = body.cpu || "";
      const config_hash = (body.config_hash || "").toLowerCase();
      const dll_crc = (body.dll_crc || "").toLowerCase();
      const version = body.version || "";
      const nonce = body.nonce || "";
      const cpu_fp = body.cpu_fp || "";
      const board_fp = body.board_fp || "";
      const timestamp = body.timestamp || now_str();
      const client_ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || null;

      if (!fp) {
        return new Response(JSON.stringify({ error: "missing fp/hwid" }), {
          status: 400, headers: cors_headers()
        });
      }

      // ★ X-Sign 校验
      const x_sign = req.headers.get("X-Sign");
      if (!x_sign) {
        return new Response(JSON.stringify({
          status: "rejected", message: "Missing X-Sign header"
        }), { status: 403, headers: cors_headers() });
      }

      const sign_valid = await verify_x_sign(
        hwid, cpu_fp, board_fp, config_hash, dll_crc, timestamp, x_sign
      );

      if (!sign_valid) {
        console.log(`[AUTH REJECT] Invalid X-Sign: FP=${fp}, HWID=${hwid}, ClientSign=${x_sign}`);
        return new Response(JSON.stringify({
          status: "rejected", message: "Invalid signature (X-Sign mismatch)"
        }), { status: 403, headers: cors_headers() });
      }

      console.log(`[AUTH REQ] IP: ${client_ip}, FP: ${fp}, HWID: ${hwid}, CPU_FP: ${cpu_fp}, BOARD_FP: ${board_fp}, Config: ${config_hash}, DLL: ${dll_crc}, Version: ${version}`);

      // ★ P1: nonce 防重放（5分钟 TTL）
      if (nonce) {
        const nonce_key = ["nonce", nonce];
        const existing = await KV.get(nonce_key);
        if (existing.value) {
          return new Response(JSON.stringify({
            status: "rejected", message: "Replay detected (duplicate nonce)"
          }), { status: 403, headers: cors_headers() });
        }
        await KV.set(nonce_key, { fp, time: now_str() }, { expireIn: 300 });
      }

      // ★ 白名单校验
      const config_hash_valid = VALID_CONFIG_HASHES.length === 0 || VALID_CONFIG_HASHES.includes(config_hash);
      const dll_crc_valid = VALID_DLL_CRCS.length === 0 || VALID_DLL_CRCS.includes(dll_crc);

      if (!config_hash_valid) {
        console.log(`[AUTH REJECT] Invalid config_hash: ${config_hash}`);
        return new Response(JSON.stringify({
          status: "rejected", message: "Invalid config_hash"
        }), { status: 403, headers: cors_headers() });
      }
      if (!dll_crc_valid) {
        console.log(`[AUTH REJECT] Invalid dll_crc: ${dll_crc}`);
        return new Response(JSON.stringify({
          status: "rejected", message: "Invalid dll_crc"
        }), { status: 403, headers: cors_headers() });
      }

      const key = ["device", fp];
      let device_entry = await KV.get<DeviceRecord>(key);
      let device = device_entry.value;

      if (!device) {
        device = create_empty_device(fp, hwid);
        device.device_code = gen_device_code();
        device.status = "pending";
        device.board = board;
        device.cpu = cpu;
        device.cpu_fp = cpu_fp;
        device.board_fp = board_fp;
        device.config_hash = config_hash;
        device.dll_crc = dll_crc;
        device.current_version = version;
        device.last_ip = client_ip;
        device.total_requests = 1;
        device.config_hash_valid = config_hash_valid;
        device.dll_crc_valid = dll_crc_valid;
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "pending",
          device_code: device.device_code,
          message: "Device registered, awaiting approval"
        }), { status: 202, headers: cors_headers() });
      }

      // 已有设备 — 更新字段
      const now = now_str();
      device.last_seen_at = now;
      device.last_request = now;
      device.total_requests = (device.total_requests || 0) + 1;
      if (client_ip) device.last_ip = client_ip;
      if (!device.board && board) device.board = board;
      if (!device.cpu && cpu) device.cpu = cpu;
      if (!device.config_hash && config_hash) device.config_hash = config_hash;
      if (!device.dll_crc && dll_crc) device.dll_crc = dll_crc;
      if (version) device.current_version = version;
      device.config_hash_valid = config_hash_valid;
      device.dll_crc_valid = dll_crc_valid;

      // ★ P2: 硬件变更检测
      if (device.status === "active") {
        let hwChanged = false;
        const notes: string[] = [];
        if (cpu_fp && device.cpu_fp && cpu_fp !== device.cpu_fp) {
          hwChanged = true;
          notes.push(`CPU changed: ${device.cpu_fp} -> ${cpu_fp}`);
        }
        if (board_fp && device.board_fp && board_fp !== device.board_fp) {
          hwChanged = true;
          notes.push(`Board changed: ${device.board_fp} -> ${board_fp}`);
        }
        if (hwChanged) {
          device.status = "hw_changed";
          const old_note = device.note ? device.note + " | " : "";
          device.note = old_note + notes.join(" | ") + ` at ${now}`;
          if (cpu_fp) device.cpu_fp = cpu_fp;
          if (board_fp) device.board_fp = board_fp;
          if (cpu) device.cpu = cpu;
          if (board) device.board = board;
          const resetDate = new Date(device.hw_change_reset_at || now);
          const daysSinceReset = (Date.now() - resetDate.getTime()) / (1000 * 60 * 60 * 24);
          if (daysSinceReset > 30) {
            device.hw_change_count = 0;
            device.hw_change_reset_at = now;
          }
          device.hw_change_count = (device.hw_change_count || 0) + 1;
          if (device.hw_change_count > 5) {
            device.status = "revoked";
            device.note = old_note + `AUTO-REVOKED: ${device.hw_change_count} hardware changes in 30 days at ${now}`;
            await KV.set(key, device);
            return new Response(JSON.stringify({
              status: "revoked",
              device_code: device.device_code,
              message: "Too many hardware changes (5+ in 30 days). Contact admin."
            }), { status: 403, headers: cors_headers() });
          }
          await KV.set(key, device);
          return new Response(JSON.stringify({
            status: "hw_changed",
            device_code: device.device_code,
            message: "Hardware change detected, re-verification required"
          }), { status: 202, headers: cors_headers() });
        }
      }

      if (!device.cpu_fp && cpu_fp) device.cpu_fp = cpu_fp;
      if (!device.board_fp && board_fp) device.board_fp = board_fp;
      if (hwid && hwid !== device.hwid) {
        if (!device.hwid_history.includes(hwid)) {
          device.hwid_history.push(hwid);
        }
        if (device.hwid_history.length > device.max_transfers + 1) {
          device.status = "pending";
        }
      }

      // 状态返回
      if (device.status === "active") {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "ok", authorized: true, device_code: device.device_code, message: "Device authorized"
        }), { headers: cors_headers() });
      } else if (device.status === "hw_changed") {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "hw_changed", device_code: device.device_code, message: "Hardware change detected, awaiting admin re-verification"
        }), { status: 202, headers: cors_headers() });
      } else if (device.status === "pending") {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "pending", device_code: device.device_code, message: "Device registered, awaiting approval"
        }), { status: 202, headers: cors_headers() });
      } else if (device.status === "revoked" || device.status === "banned" || device.status === "expired") {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "rejected", device_code: device.device_code, message: `Device ${device.status}`
        }), { status: 403, headers: cors_headers() });
      } else {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "pending", device_code: device.device_code, message: "Unknown status, awaiting review"
        }), { status: 202, headers: cors_headers() });
      }
    } catch (e) {
      return new Response(JSON.stringify({ error: "invalid request", detail: String(e) }), {
        status: 400, headers: cors_headers()
      });
    }
  }

  // ============ /admin/approve ============
  if (path === "/admin/approve" && method === "POST") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    try {
      const body = await req.json();
      const fp = body.fp;
      if (!fp) return new Response(JSON.stringify({ error: "missing fp" }), { status: 400, headers: cors_headers() });
      const key = ["device", fp];
      const entry = await KV.get<DeviceRecord>(key);
      if (!entry.value) return new Response(JSON.stringify({ error: "device not found" }), { status: 404, headers: cors_headers() });
      const device = entry.value;
      device.status = "active";
      device.activated_at = now_str();
      if (body.note) device.note = body.note;
      if (body.allowed_versions?.length > 0) device.allowed_versions = body.allowed_versions;
      if (body.expires_at) device.expires_at = body.expires_at;
      await KV.set(key, device);
      return new Response(JSON.stringify({ success: true, fp: device.fp, device_code: device.device_code, status: device.status, message: "Device approved" }), { headers: cors_headers() });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: cors_headers() });
    }
  }

  // ============ /admin/revoke ============
  if (path === "/admin/revoke" && method === "POST") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    try {
      const body = await req.json();
      const fp = body.fp;
      if (!fp) return new Response(JSON.stringify({ error: "missing fp" }), { status: 400, headers: cors_headers() });
      const key = ["device", fp];
      const entry = await KV.get<DeviceRecord>(key);
      if (!entry.value) return new Response(JSON.stringify({ error: "device not found" }), { status: 404, headers: cors_headers() });
      const device = entry.value;
      device.status = "revoked";
      if (body.reason) device.note = `Revoked: ${body.reason}`;
      else device.note = `Revoked at ${now_str()}`;
      device.last_request = now_str();
      await KV.set(key, device);
      return new Response(JSON.stringify({ success: true, fp: device.fp, status: device.status, message: "Device revoked" }), { headers: cors_headers() });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: cors_headers() });
    }
  }

  // ============ /admin/ban ============
  if (path === "/admin/ban" && method === "POST") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    try {
      const body = await req.json();
      const fp = body.fp;
      if (!fp) return new Response(JSON.stringify({ error: "missing fp" }), { status: 400, headers: cors_headers() });
      const key = ["device", fp];
      const entry = await KV.get<DeviceRecord>(key);
      if (!entry.value) return new Response(JSON.stringify({ error: "device not found" }), { status: 404, headers: cors_headers() });
      const device = entry.value;
      device.status = "banned";
      if (body.reason) device.note = `BANNED: ${body.reason}`;
      else device.note = `Banned at ${now_str()}`;
      device.last_request = now_str();
      await KV.set(key, device);
      return new Response(JSON.stringify({ success: true, fp: device.fp, status: device.status, message: "Device banned" }), { headers: cors_headers() });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: cors_headers() });
    }
  }

  // ============ /admin/unban ============
  if (path === "/admin/unban" && method === "POST") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    try {
      const body = await req.json();
      const fp = body.fp;
      if (!fp) return new Response(JSON.stringify({ error: "missing fp" }), { status: 400, headers: cors_headers() });
      const key = ["device", fp];
      const entry = await KV.get<DeviceRecord>(key);
      if (!entry.value) return new Response(JSON.stringify({ error: "device not found" }), { status: 404, headers: cors_headers() });
      const device = entry.value;
      if (!["banned", "revoked", "hw_changed"].includes(device.status)) {
        return new Response(JSON.stringify({ error: "device is not banned/revoked/hw_changed", current_status: device.status }), { status: 400, headers: cors_headers() });
      }
      device.status = "pending";
      const old_note = device.note ? device.note + " | " : "";
      device.note = old_note + `Restored from ${device.status} at ${now_str()}`;
      await KV.set(key, device);
      return new Response(JSON.stringify({ success: true, fp: device.fp, status: device.status, message: `Device restored from ${device.status}, back to pending` }), { headers: cors_headers() });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: cors_headers() });
    }
  }

  // ============ /admin/delete-device ============
  if (path === "/admin/delete-device" && method === "POST") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    try {
      const body = await req.json();
      const fp = body.fp;
      if (!fp) return new Response(JSON.stringify({ error: "missing fp" }), { status: 400, headers: cors_headers() });
      const key = ["device", fp];
      await KV.delete(key);
      return new Response(JSON.stringify({ success: true, fp, message: "Device deleted" }), { headers: cors_headers() });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: cors_headers() });
    }
  }

  // ============ /admin/devices ============
  if (path === "/admin/devices" && method === "GET") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    const devices: any[] = [];
    const limit = parseInt(url.searchParams.get("limit") || "50");
    const status_filter = url.searchParams.get("status");
    for await (const entry of KV.list<DeviceRecord>({ prefix: ["device"] })) {
      if (entry.value) {
        if (status_filter && entry.value.status !== status_filter) continue;
        devices.push(entry.value);
        if (devices.length >= limit) break;
      }
    }
    return new Response(JSON.stringify({ count: devices.length, devices }, null, 2), { headers: cors_headers() });
  }

  // ============ /admin/schema ============
  if (path === "/admin/schema" && method === "GET") {
    if (!check_admin_auth(req)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    const sample = create_empty_device("SAMPLE", "SAMPLE");
    return new Response(JSON.stringify({
      version: "2.7.1",
      description: "F210 Device Record Schema",
      fields: Object.keys(sample).map(k => ({ field: k, type: typeof (sample as any)[k], sample: (sample as any)[k] }))
    }, null, 2), { headers: cors_headers() });
  }

  // ============ /cron/expire-devices ============
  if (path === "/cron/expire-devices" && method === "GET") {
    const cron_key = req.headers.get("X-Cron-Key");
    const ua = (req.headers.get("User-Agent") || "").toLowerCase();
    if (!cron_key && !ua.includes("deno")) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    if (cron_key && cron_key !== ADMIN_KEY) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: cors_headers() });
    }
    let expired_count = 0;
    const now = now_str();
    for await (const entry of KV.list<DeviceRecord>({ prefix: ["device"] })) {
      if (!entry.value) continue;
      const device = entry.value;
      if (device.status === "active" && device.expires_at) {
        if (device.expires_at < now) {
          device.status = "expired";
          device.note = (device.note ? device.note + " | " : "") + `Expired at ${now}`;
          device.last_request = now;
          await KV.set(entry.key, device);
          expired_count++;
        }
      }
    }
    console.log(`[CRON] expire-devices: ${expired_count} devices expired at ${now}`);
    return new Response(JSON.stringify({ success: true, expired_count, time: now }), { headers: cors_headers() });
  }

  // ============ /health ============
  if (path === "/health" && method === "GET") {
    return new Response(JSON.stringify({ status: "ok", version: "2.7.1", time: now_str() }), { headers: cors_headers() });
  }

  return new Response(JSON.stringify({ error: "not found", path }), { status: 404, headers: cors_headers() });
}

console.log(`F210 Auth Server v2.7.1 starting...`);

Deno.cron(
  "expire-devices-daily",
  "0 0 * * *",
  async () => {
    const now = now_str();
    let expired_count = 0;
    try {
      for await (const entry of KV.list<DeviceRecord>({ prefix: ["device"] })) {
        if (!entry.value) continue;
        const device = entry.value;
        if (device.status === "active" && device.expires_at) {
          if (device.expires_at < now) {
            device.status = "expired";
            device.note = (device.note ? device.note + " | " : "") + `Expired at ${now}`;
            device.last_request = now;
            await KV.set(entry.key, device);
            expired_count++;
          }
        }
      }
      console.log(`[CRON] expire-devices: ${expired_count} devices expired at ${now}`);
    } catch (e) {
      console.error(`[CRON] expire-devices failed: ${String(e)}`);
    }
  }
);

Deno.serve({ port: 8000 }, handler);