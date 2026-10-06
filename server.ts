// ============================================================
// server.ts - F210 Ball Physics Auth Server (Final Version)
// Deno Deploy + Deno KV
// ============================================================

// ---------- 类型定义 ----------

type DeviceStatus = "initializing" | "active" | "revoked" | "expired" | "suspended";

interface Device {
  // ① 核心标识组
  fp: string;
  board: string;
  cpu: string;

  // ② 状态与生命周期组
  status: DeviceStatus;
  expires_at: string;          // YYYY-MM-DD HH:MM:SS，空串=未设置
  created_at: string;          // YYYY-MM-DD HH:MM:SS
  activated_at: string;        // YYYY-MM-DD HH:MM:SS，空串=未激活
  last_seen: string;           // YYYY-MM-DD HH:MM:SS，空串=未上线

  // ③ 版本与权限组
  version: string;
  max_pcs: number;
  features: string[];
  trial: boolean;

  // ④ 换机与风控组
  transfer_count: number;
  hwid_history: string[];      // JSON string 数组，记录历史硬件ID

  // ⑤ 运营与商业化组
  ban_reason: string;
  note: string;
  contact: string;
  order_ref: string;
  price_tier: string;

  // ⑥ 来源与交易组
  source_platform: string;
  platform_id: string;
  platform_nick: string;
  wechat_id: string;
  wechat_nick: string;
  purchase_date: string;       // YYYY-MM-DD HH:MM:SS，空串=未设置
  payment_amount: number;
  subscription_type: "month" | "year" | "permanent";

  // ⑦ 行为统计组
  request_count: number;
  last_request: string;        // YYYY-MM-DD HH:MM:SS
  last_ip: string;
}

// ---------- 工具函数 ----------

function nowStr(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function parseUnixTs(ts: string | number): Date {
  return new Date(Number(ts) * 1000);
}

function formatTimeWindow(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// HMAC-SHA256 签名验证
async function verifySignature(
  payload: string,
  sigHex: string,
  secret: string
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sigBytes = new Uint8Array(
    sigHex.match(/.{1,2}/g)!.map((b) => parseInt(b, 16))
  );
  return await crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes,
    new TextEncoder().encode(payload)
  );
}

// 获取客户端 IP
function getClientIP(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      ?? req.headers.get("x-real-ip")
      ?? "unknown";
}

// 默认设备模板（用于自动注册 initializing）
function defaultDevice(fp: string, board: string, cpu: string, now: string, ip: string): Device {
  return {
    fp,
    board,
    cpu,
    status: "initializing",
    expires_at: "",
    created_at: now,
    activated_at: "",
    last_seen: "",
    version: "F210-Ball-Lite-v1.0",
    max_pcs: 1,
    features: ["ball_physics_lite"],
    trial: false,
    transfer_count: 0,
    hwid_history: [],
    ban_reason: "",
    note: "自动注册-待审核",
    contact: "",
    order_ref: "",
    price_tier: "",
    source_platform: "",
    platform_id: "",
    platform_nick: "",
    wechat_id: "",
    wechat_nick: "",
    purchase_date: "",
    payment_amount: 0,
    subscription_type: "month",
    request_count: 1,
    last_request: now,
    last_ip: ip,
  };
}

// ---------- 主入口 ----------

const kv = await Deno.openKv();

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;

  // ---- 健康检查 ----
  if (path === "/health" && req.method === "GET") {
    return json({ status: "ok", time: nowStr() });
  }

  // ---- 客户端鉴权接口 ----
  if (path === "/license/check" && req.method === "POST") {
    return handleCheck(req);
  }

  // ---- 管理接口 ----
  if (path === "/admin/license" && req.method === "POST") {
    const adminToken = req.headers.get("x-admin-token");
    if (adminToken !== Deno.env.get("F210_ADMIN_TOKEN")) {
      return json({ error: "unauthorized" }, 401);
    }
    return handleAdmin(req);
  }

  return json({ error: "not found" }, 404);
});

// ============================================================
// 客户端鉴权
// ============================================================
async function handleCheck(req: Request): Promise<Response> {
  const secret = Deno.env.get("F210_SECRET");
  if (!secret) return json({ error: "server misconfigured" }, 500);

  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid json" }, 400);
  }

  const { fp, board, cpu, ts, nonce, sig, version } = body;
  if (!fp || !board || !cpu || !ts || !nonce || !sig) {
    return json({ error: "missing fields" }, 400);
  }

  // ---- 频率限制：1分钟5次 ----
  const rateKey = ["rate_limit", fp];
  const rateRec = await kv.get<{ count: number; window_start: string }>(rateKey);
  const now = new Date();
  const nowTs = Math.floor(now.getTime() / 1000);

  if (rateRec.value) {
    const windowStart = new Date(rateRec.value.window_start).getTime() / 1000;
    if (nowTs - windowStart < 60) {
      if (rateRec.value.count >= 5) {
        return json({
          status: "rate_limited",
          retry_after: 60 - Math.floor(nowTs - windowStart),
        }, 429);
      }
    } else {
      // 窗口过期，重置
      await kv.set(rateKey, { count: 1, window_start: nowStr() });
    }
  } else {
    await kv.set(rateKey, { count: 1, window_start: nowStr() });
  }

  // ---- 签名验证 ----
  const payload = `${fp}|${board}|${cpu}|${ts}|${nonce}`;
  const sigOk = await verifySignature(payload, sig, secret);
  if (!sigOk) {
    return json({ status: "invalid_signature" }, 403);
  }

  // ---- 时间窗校验 ±300s ----
  const clientTs = Number(ts);
  if (Math.abs(nowTs - clientTs) > 300) {
    return json({ status: "replay_or_clock_skew" }, 403);
  }

  // ---- nonce 防重放（5分钟窗口） ----
  const nonceKey = ["nonce", nonce];
  const existing = await kv.get(nonceKey);
  if (existing.value) {
    return json({ status: "replay_detected" }, 403);
  }
  await kv.set(nonceKey, { fp, ts }, { expireIn: 300_000 }); // 5分钟过期

  // ---- 频率计数 +1（签名通过） ----
  if (rateRec.value && nowTs - (new Date(rateRec.value.window_start).getTime() / 1000) < 60) {
    await kv.set(rateKey, {
      count: rateRec.value.count + 1,
      window_start: rateRec.value.window_start,
    });
  }

  const ip = getClientIP(req);
  const nowStrVal = nowStr();

  // ---- 查询设备 ----
  const devRec = await kv.get<Device>(["device", fp]);

  // ---- 新用户：自动建 initializing 记录 ----
  if (!devRec.value) {
    const newDev = defaultDevice(fp, board, cpu, nowStrVal, ip);
    await kv.set(["device", fp], newDev);
    return json({
      status: "not_authorized",
      message: "设备已登记，请联系作者完成授权",
    }, 403);
  }

  const dev = devRec.value;

  // ---- 更新行为统计（签名通过即写） ----
  const updatedDev: Device = {
    ...dev,
    request_count: dev.request_count + 1,
    last_request: nowStrVal,
    last_ip: ip,
  };

  // ---- 状态判断 ----
  if (dev.status === "active") {
    // 检查过期
    if (dev.expires_at && dev.expires_at !== "") {
      const expDate = new Date(dev.expires_at.replace(" ", "T"));
      if (now > expDate) {
        updatedDev.status = "expired";
        await kv.set(["device", fp], updatedDev);
        return json({ status: "expired" }, 403);
      }
    }

    // 首次激活时间
    if (!dev.activated_at || dev.activated_at === "") {
      updatedDev.activated_at = nowStrVal;
    }

    // 全部检查通过 → 更新 last_seen
    updatedDev.last_seen = nowStrVal;
    await kv.set(["device", fp], updatedDev);

    return json({
      status: "ok",
      expires_at: dev.expires_at,
      version: dev.version,
      features: dev.features,
    });
  }

  // ---- 非 active 状态：更新统计后返回对应提示 ----
  await kv.set(["device", fp], updatedDev);

  if (dev.status === "initializing") {
    return json({ status: "not_authorized", message: "设备待审核，请联系作者" }, 403);
  } else if (dev.status === "expired") {
    return json({ status: "expired" }, 403);
  } else if (dev.status === "revoked") {
    return json({ status: "revoked" }, 403);
  } else if (dev.status === "suspended") {
    return json({ status: "suspended" }, 403);
  } else {
    return json({ status: "not_authorized" }, 403);
  }
}

// ============================================================
// 管理接口
// ============================================================
async function handleAdmin(req: Request): Promise<Response> {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid json" }, 400);
  }

  const { action } = body;
  if (!action) return json({ error: "missing action" }, 400);

  // ---- add ----
  if (action === "add") {
    const { fp, board, cpu, ...rest } = body;
    if (!fp || !board || !cpu) return json({ error: "fp/board/cpu required" }, 400);

    const existing = await kv.get<Device>(["device", fp]);
    if (existing.value) return json({ error: "device already exists" }, 409);

    const now = nowStr();
    const newDev: Device = {
      ...defaultDevice(fp, board, cpu, now, ""),
      status: rest.status ?? "active",
      expires_at: rest.expires_at ?? "",
      version: rest.version ?? "F210-Ball-Lite-v1.0",
      max_pcs: rest.max_pcs ?? 1,
      features: rest.features ?? ["ball_physics_lite"],
      trial: rest.trial ?? false,
      note: rest.note ?? "",
      contact: rest.contact ?? "",
      order_ref: rest.order_ref ?? "",
      price_tier: rest.price_tier ?? "",
      source_platform: rest.source_platform ?? "",
      platform_id: rest.platform_id ?? "",
      platform_nick: rest.platform_nick ?? "",
      wechat_id: rest.wechat_id ?? "",
      wechat_nick: rest.wechat_nick ?? "",
      purchase_date: rest.purchase_date ?? now,
      payment_amount: rest.payment_amount ?? 0,
      subscription_type: rest.subscription_type ?? "month",
      request_count: 0,
      last_request: "",
      last_ip: "",
    };
    await kv.set(["device", fp], newDev);
    return json({ status: "ok", device: newDev });
  }

  // ---- update ----
  if (action === "update") {
    const { fp, updates } = body;
    if (!fp || !updates) return json({ error: "fp and updates required" }, 400);

    const devRec = await kv.get<Device>(["device", fp]);
    if (!devRec.value) return json({ error: "device not found" }, 404);

    const updated: Device = { ...devRec.value, ...updates };
    await kv.set(["device", fp], updated);
    return json({ status: "ok", device: updated });
  }

  // ---- revoke ----
  if (action === "revoke") {
    const { fp, reason } = body;
    if (!fp) return json({ error: "fp required" }, 400);

    const devRec = await kv.get<Device>(["device", fp]);
    if (!devRec.value) return json({ error: "device not found" }, 404);

    const updated: Device = {
      ...devRec.value,
      status: "revoked",
      ban_reason: reason ?? "管理员拉黑",
    };
    await kv.set(["device", fp], updated);
    return json({ status: "ok" });
  }

  // ---- suspend ----
  if (action === "suspend") {
    const { fp, reason } = body;
    if (!fp) return json({ error: "fp required" }, 400);

    const devRec = await kv.get<Device>(["device", fp]);
    if (!devRec.value) return json({ error: "device not found" }, 404);

    const updated: Device = {
      ...devRec.value,
      status: "suspended",
      ban_reason: reason ?? "管理员暂停",
    };
    await kv.set(["device", fp], updated);
    return json({ status: "ok" });
  }

  // ---- unsuspend ----
  if (action === "unsuspend") {
    const { fp } = body;
    if (!fp) return json({ error: "fp required" }, 400);

    const devRec = await kv.get<Device>(["device", fp]);
    if (!devRec.value) return json({ error: "device not found" }, 404);

    const updated: Device = {
      ...devRec.value,
      status: "active",
      ban_reason: "",
    };
    await kv.set(["device", fp], updated);
    return json({ status: "ok" });
  }

  // ---- replace（换机） ----
  if (action === "replace") {
    const { old_fp, new_fp, new_board, new_cpu } = body;
    if (!old_fp || !new_fp || !new_board || !new_cpu) {
      return json({ error: "old_fp/new_fp/new_board/new_cpu required" }, 400);
    }

    // 旧设备拉黑
    const oldRec = await kv.get<Device>(["device", old_fp]);
    if (oldRec.value) {
      const oldUpdated: Device = {
        ...oldRec.value,
        status: "revoked",
        ban_reason: "换机-旧设备拉黑",
      };
      await kv.set(["device", old_fp], oldUpdated);
    }

    // 新设备：如果已存在就改状态，不存在就新建
    const newRec = await kv.get<Device>(["device", new_fp]);
    const now = nowStr();
    if (newRec.value) {
      const newUpdated: Device = {
        ...newRec.value,
        status: "active",
        board: new_board,
        cpu: new_cpu,
        transfer_count: newRec.value.transfer_count + 1,
        hwid_history: [...newRec.value.hwid_history, old_fp],
        activated_at: newRec.value.activated_at || now,
        request_count: 0,
        last_request: "",
        last_ip: "",
      };
      await kv.set(["device", new_fp], newUpdated);
    } else {
      const newDev = defaultDevice(new_fp, new_board, new_cpu, now, "");
      newDev.status = "active";
      newDev.transfer_count = 1;
      newDev.hwid_history = [old_fp];
      newDev.activated_at = now;
      await kv.set(["device", new_fp], newDev);
    }

    return json({ status: "ok", message: "换机完成" });
  }

  // ---- list ----
  if (action === "list") {
    const devices: Device[] = [];
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      devices.push(e.value);
    }
    return json({ count: devices.length, devices });
  }

  // ---- search ----
  if (action === "search") {
    const { field, keyword } = body;
    if (!field || keyword === undefined) return json({ error: "field and keyword required" }, 400);

    const results: Device[] = [];
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      const val = (e.value as any)[field];
      if (val !== undefined && String(val).includes(String(keyword))) {
        results.push(e.value);
      }
    }
    return json({ count: results.length, devices: results });
  }

  // ---- pending_list（initializing 状态） ----
  if (action === "pending_list") {
    const pending: Device[] = [];
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      if (e.value.status === "initializing") pending.push(e.value);
    }
    return json({ count: pending.length, devices: pending });
  }

  // ---- stats ----
  if (action === "stats") {
    let total = 0, active = 0, initializing = 0, expired = 0, revoked = 0, suspended = 0;
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      total++;
      if (e.value.status === "active") active++;
      else if (e.value.status === "initializing") initializing++;
      else if (e.value.status === "expired") expired++;
      else if (e.value.status === "revoked") revoked++;
      else if (e.value.status === "suspended") suspended++;
    }
    return json({ total, active, initializing, expired, revoked, suspended });
  }

  // ---- revenue ----
  if (action === "revenue") {
    let totalRevenue = 0;
    const byType: Record<string, { count: number; revenue: number }> = {
      month: { count: 0, revenue: 0 },
      year: { count: 0, revenue: 0 },
      permanent: { count: 0, revenue: 0 },
    };
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      const d = e.value;
      if (d.status === "active" || d.status === "expired") {
        totalRevenue += d.payment_amount;
        if (byType[d.subscription_type]) {
          byType[d.subscription_type].count++;
          byType[d.subscription_type].revenue += d.payment_amount;
        }
      }
    }
    return json({ total_revenue: totalRevenue, by_subscription_type: byType });
  }

  // ---- expire_soon ----
  if (action === "expire_soon") {
    const { days } = body;
    const d = days ?? 7;
    const threshold = new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);
    const expiring: Device[] = [];
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      if (e.value.status === "active" && e.value.expires_at) {
        const expDate = e.value.expires_at.slice(0, 10);
        if (expDate <= threshold) expiring.push(e.value);
      }
    }
    return json({ count: expiring.length, devices: expiring });
  }

  // ---- top_users ----
  if (action === "top_users") {
    const { limit } = body;
    const l = limit ?? 10;
    const all: Device[] = [];
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      all.push(e.value);
    }
    all.sort((a, b) => b.request_count - a.request_count);
    return json({ top: all.slice(0, l) });
  }

  // ---- suspicious ----
  if (action === "suspicious") {
    const suspicious: { fp: string; reason: string; device: Device }[] = [];
    for await (const e of kv.list<Device>({ prefix: ["device"] })) {
      const d = e.value;
      // 被拒仍在频繁请求
      if (d.status !== "active" && d.request_count > 20) {
        suspicious.push({ fp: d.fp, reason: "非活跃设备高频请求", device: d });
      }
      // 换机次数异常
      if (d.transfer_count > 3) {
        suspicious.push({ fp: d.fp, reason: "换机次数异常", device: d });
      }
    }
    return json({ count: suspicious.length, list: suspicious });
  }

  return json({ error: `unknown action: ${action}` }, 400);
}

// ---------- 响应辅助 ----------

function json(data: any, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}