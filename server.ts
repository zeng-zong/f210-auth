/**
 * server.ts v2.3.3
 * F210 Auth Server - Deno Deploy / Deno KV
 */

// ============ 配置 ============
const ADMIN_KEY = Deno.env.get("ADMIN_KEY") || "xK9#mP2$vL7@qW3!nR5&jY8";
const KV = await Deno.openKv();

// ============ 哈希白名单 ============
// config_hash：暂不需要，空数组=跳过校验
const VALID_CONFIG_HASHES: string[] = [];

// dll_crc：重要！填真实 DLL CRC32，非空=启用校验
// 获取方法：编译 DLL 后用 CRC32 工具算 bridge.dll 的值，填进来
const VALID_DLL_CRCS: string[] = [
  "6B354021"  // 等 DLL 端实现真实 CRC 后，编译出来填这里
];

// ============ 工具函数 ============
function now_str(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
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
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return h;
}

// ============ 设备数据结构 ============
interface DeviceRecord {
  fp: string;
  device_code: string | null;
  hwid: string;
  status: "initializing" | "pending" | "active" | "revoked" | "banned";
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
  config_hash: string;
  dll_crc: string;
  config_hash_valid?: boolean;
  dll_crc_valid?: boolean;
}

function create_empty_device(fp: string, hwid: string): DeviceRecord {
  const now = now_str();
  return {
    fp, device_code: null, hwid,
    status: "initializing",
    created_at: now, last_seen_at: now, last_request: now,
    activated_at: null, expires_at: null,
    allowed_versions: [], current_version: null,
    hwid_history: [hwid], transfer_count: 0, max_transfers: 3,
    note: "", contact: "",
    order_id: null, purchase_date: null, license_type: null,
    total_requests: 0, last_ip: null,
    board: "", cpu: "", config_hash: "", dll_crc: "",
  };
}

// ============ 认证中间件 ============
function check_admin_auth(req: Request): boolean {
  const auth = req.headers.get("Authorization");
  if (!auth) return false;
  return auth === `Bearer ${ADMIN_KEY}`;
}

// ============ 路由 ============
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
      const config_hash = (body.config_hash || "").toUpperCase();
      const dll_crc = (body.dll_crc || "").toUpperCase();
      const version = body.version || "";
      const client_ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || null;

      if (!fp) {
        return new Response(JSON.stringify({ error: "missing fp/hwid" }), {
          status: 400, headers: cors_headers()
        });
      }

      // 分开校验
      // config_hash：白名单为空 → 跳过
      const config_hash_valid = VALID_CONFIG_HASHES.length === 0 || !config_hash || VALID_CONFIG_HASHES.includes(config_hash);
      // dll_crc：白名单为空 → 跳过；非空 → 严格校验
      const dll_crc_valid = VALID_DLL_CRCS.length === 0 || !dll_crc || VALID_DLL_CRCS.includes(dll_crc);

      const key = ["device", fp];
      let device_entry = await KV.get<DeviceRecord>(key);
      let device = device_entry.value;

      if (!device) {
        device = create_empty_device(fp, hwid);
        device.device_code = gen_device_code();
        device.status = "pending";
        device.board = board;
        device.cpu = cpu;
        device.config_hash = config_hash;
        device.dll_crc = dll_crc;
        device.current_version = version;
        device.last_ip = client_ip;
        device.total_requests = 1;
        device.config_hash_valid = config_hash_valid;
        device.dll_crc_valid = dll_crc_valid;

        // DLL CRC 不合法 → 标记（即使白名单为空也不触发这里）
        if (!dll_crc_valid) {
          device.note = `Invalid DLL CRC: ${dll_crc} at ${now_str()}`;
        }

        await KV.set(key, device);

        return new Response(JSON.stringify({
          status: "pending",
          device_code: device.device_code,
          message: "Device registered, awaiting approval"
        }), { status: 202, headers: cors_headers() });
      }

      // 已有设备
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

      // DLL CRC 异常追踪
      if (!dll_crc_valid) {
        const old_note = device.note ? device.note + " | " : "";
        device.note = old_note + `Invalid DLL CRC: ${dll_crc} at ${now}`;
      }

      // HWID 变化检测
      if (hwid && hwid !== device.hwid) {
        if (!device.hwid_history.includes(hwid)) {
          device.hwid_history.push(hwid);
        }
        if (device.hwid_history.length > device.max_transfers + 1) {
          device.status = "pending";
        }
      }

      if (device.status === "active") {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "ok", authorized: true, device_code: device.device_code, message: "Device authorized"
        }), { headers: cors_headers() });

      } else if (device.status === "pending" || device.status === "initializing") {
        await KV.set(key, device);
        return new Response(JSON.stringify({
          status: "pending", device_code: device.device_code, message: "Device registered, awaiting approval"
        }), { status: 202, headers: cors_headers() });

      } else if (device.status === "revoked" || device.status === "banned") {
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
      device.last_request = now_str();

      await KV.set(key, device);
      return new Response(JSON.stringify({ success: true, fp: device.fp, status: device.status, message: "Device revoked" }), { headers: cors_headers() });
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
      version: "2.3.3",
      description: "F210 Device Record Schema",
      fields: Object.keys(sample).map(k => ({ field: k, type: typeof (sample as any)[k], sample: (sample as any)[k] }))
    }, null, 2), { headers: cors_headers() });
  }

  // ============ /health ============
  if (path === "/health" && method === "GET") {
    return new Response(JSON.stringify({ status: "ok", version: "2.3.3", time: now_str() }), { headers: cors_headers() });
  }

  return new Response(JSON.stringify({ error: "not found", path }), { status: 404, headers: cors_headers() });
}

console.log(`F210 Auth Server v2.3.3 starting...`);
Deno.serve({ port: 8000 }, handler);