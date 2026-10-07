// server.ts — F210 Auth Server v2.0
// Deno Deploy 原生 KV

/* ==================== 配置 ==================== */
const TRANSFER_LIMIT = 3;
const COOLDOWN_DAYS = 7;
const ACTIVE = "active";
const INITIALIZING = "initializing";
const REVOKED = "revoked";
const SUSPENDED = "suspended";

// DLL 哈希白名单（编译后填入真实值）
const VALID_DLL_HASHES: Set<string> = new Set([
  // "5A8DF37F"
]);

/* ==================== KV ==================== */
const kv = await Deno.openKv();

/* ==================== 类型 ==================== */
interface Device {
  fp: string;
  board: string;
  cpu: string;
  status: string;
  device_code: string;
  dll_hash: string;
  version: string;
  transfer_count: number;
  last_transfer_at: string;       // ISO 格式
  transfer_cooldown_days: number;
  hwid_history: string[];
  activated_at: string;
  last_seen: string;
  last_ip: string;
  ban_reason: string;
  request_count: number;
  created_at: string;
  expires_at: string;
  max_pcs: number;
  features: string[];
  trial: boolean;
  note: string;
  contact: string;
  order_ref: string;
  price_tier: string;
  source_platform: string;
  platform_id: string;
  platform_nick: string;
  wechat_id: string;
  wechat_nick: string;
  purchase_date: string;
  payment_amount: number;
  subscription_type: string;
}

/* ==================== 工具 ==================== */
function nowISO(): string {
  return new Date().toISOString().slice(0, 19).replace("T", " ");
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/* ==================== /license/check ==================== */
async function handleCheck(req: Request): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "invalid json" }, 400); }

  const fp: string = body.fp || "";
  const board: string = body.board || "";
  const cpu: string = body.cpu || "";
  const ts: number = body.ts || 0;
  const nonce: string = body.nonce || "";
  const sig: string = body.sig || "";
  const dll_hash: string = body.dll_hash || "";
  const device_code: string = body.device_code || "";
  const client_version: string = body.version || "";

  // fp 格式校验
  if (!fp || fp.length !== 32) return json({ error: "invalid fp" }, 400);

  // DLL 完整性校验（可选严格模式）
  if (dll_hash && VALID_DLL_HASHES.size > 0 && !VALID_DLL_HASHES.has(dll_hash)) {
    console.warn(`[WARN] Unknown dll_hash=${dll_hash} fp=${fp}`);
    // return json({ status: "not_authorized", message: "客户端校验失败" }, 403);
  }

  // 查设备
  const devKey = ["device", fp];
  const devRec = await kv.get<Device>(devKey);

  if (devRec.value) {
    const dev = devRec.value;

    // 更新心跳
    dev.last_seen = nowISO();
    dev.request_count = (dev.request_count || 0) + 1;
    if (dll_hash) dev.dll_hash = dll_hash;
    if (device_code) dev.device_code = device_code;

    if (dev.status === ACTIVE) {
      await kv.set(devKey, dev);
      return json({ status: "ok", fp, device_code: dev.device_code });
    }

    if (dev.status === REVOKED) {
      return json({ status: "revoked", message: "设备已被拉黑" }, 403);
    }

    if (dev.status === SUSPENDED) {
      return json({ status: "suspended", message: "设备已暂停" }, 403);
    }

    if (dev.status === INITIALIZING) {
      await kv.set(devKey, dev);
      return json({ status: "not_authorized", message: "设备已登记，请联系作者完成授权", device_code: dev.device_code }, 403);
    }

    await kv.set(devKey, dev);
    return json({ status: dev.status }, 403);
  }

  // 新设备 → 自动注册 initializing
  const now = nowISO();
  const newDev: Device = {
    fp,
    board,
    cpu,
    status: INITIALIZING,
    device_code,
    dll_hash,
    version: client_version,
    transfer_count: 0,
    last_transfer_at: "",
    transfer_cooldown_days: COOLDOWN_DAYS,
    hwid_history: [fp],
    activated_at: "",
    last_seen: now,
    last_ip: req.headers.get("x-forwarded-for") || "",
    ban_reason: "",
    request_count: 1,
    created_at: now,
    expires_at: "",
    max_pcs: 1,
    features: [],
    trial: false,
    note: "",
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
  };

  // 原子创建
  const createRes = await kv.atomic()
    .check({ key: devKey, versionstamp: null })
    .set(devKey, newDev)
    .commit();

  if (!createRes.ok) {
    // 并发冲突，重新读取
    const retry = await kv.get<Device>(devKey);
    if (retry.value) {
      return json({ status: "not_authorized", message: "设备已登记，请联系作者完成授权", device_code: retry.value.device_code }, 403);
    }
  }

  // 同时建立 device_code → fp 映射
  if (device_code) {
    await kv.set(["device_code", device_code], fp);
  }

  return json({ status: "not_authorized", message: "设备已登记，请联系作者完成授权", device_code }, 403);
}

/* ==================== /admin/pending ==================== */
async function handlePending(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");

  if (code) {
    // 按短码查
    const fpRes = await kv.get<string>(["device_code", code]);
    if (!fpRes.value) return json({ error: "设备码不存在" }, 404);
    const devRes = await kv.get<Device>(["device", fpRes.value]);
    if (!devRes.value) return json({ error: "设备记录不存在" }, 404);
    return json({ device: devRes.value });
  }

  // 列出所有 initializing 设备
  const pending: Device[] = [];
  const iter = kv.list<Device>({ prefix: ["device"] });
  for await (const entry of iter) {
    if (entry.value.status === INITIALIZING) {
      pending.push(entry.value);
    }
  }

  return json({ count: pending.length, pending });
}

/* ==================== /admin/activate ==================== */
async function handleActivate(req: Request): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "invalid json" }, 400); }

  const fp: string = body.fp || "";
  const device_code: string = body.device_code || "";
  const expires_at: string = body.expires_at || "";
  const note: string = body.note || "";
  const contact: string = body.contact || "";

  let targetFp = fp;

  // 如果传的是短码，先解析
  if (!fp && device_code) {
    const fpRes = await kv.get<string>(["device_code", device_code]);
    if (!fpRes.value) return json({ error: "设备码不存在" }, 404);
    targetFp = fpRes.value;
  }

  if (!targetFp) return json({ error: "fp or device_code required" }, 400);

  const devKey = ["device", targetFp];
  const devRec = await kv.get<Device>(devKey);
  if (!devRec.value) return json({ error: "设备不存在" }, 404);

  const dev = devRec.value;
  dev.status = ACTIVE;
  dev.activated_at = nowISO();
  dev.last_seen = nowISO();
  if (expires_at) dev.expires_at = expires_at;
  if (note) dev.note = note;
  if (contact) dev.contact = contact;

  const res = await kv.atomic()
    .check({ key: devKey, versionstamp: devRec.versionstamp })
    .set(devKey, dev)
    .commit();

  if (!res.ok) return json({ error: "并发冲突，请重试" }, 409);

  return json({ status: "ok", fp: targetFp, device_code: dev.device_code, expires_at: dev.expires_at });
}

/* ==================== /admin/replace（换机） ==================== */
async function handleReplace(req: Request): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "invalid json" }, 400); }

  const old_fp: string = body.old_fp || "";
  const new_fp: string = body.new_fp || "";

  if (!old_fp || !new_fp || old_fp === new_fp) return json({ error: "invalid params" }, 400);

  const oldKey = ["device", old_fp];
  const newKey = ["device", new_fp];

  const oldRec = await kv.get<Device>(oldKey);
  const newRec = await kv.get<Device>(newKey);

  if (!oldRec.value) return json({ error: "旧设备不存在" }, 404);

  const oldDev = oldRec.value;

  // 冷却期检查
  if (oldDev.last_transfer_at) {
    const lastTransfer = new Date(oldDev.last_transfer_at.replace(" ", "T"));
    const daysSince = (Date.now() - lastTransfer.getTime()) / 86400000;
    const cooldown = oldDev.transfer_cooldown_days || COOLDOWN_DAYS;
    if (daysSince < cooldown) {
      return json({ error: `冷却期未过，剩余 ${Math.ceil(cooldown - daysSince)} 天` }, 403);
    }
  }

  // 换机次数上限
  if (oldDev.transfer_count >= TRANSFER_LIMIT) {
    return json({ error: `换机次数已达上限 (${TRANSFER_LIMIT})` }, 403);
  }

  // 新设备检查
  if (newRec.value) {
    const newDev = newRec.value;
    if (newDev.status === ACTIVE) {
      return json({ error: "新设备已有活跃授权（疑似倒卖）" }, 403);
    }
    // 历史冲突检查
    const otherFps = newDev.hwid_history.filter(h => h !== old_fp);
    if (otherFps.length > 0) {
      // 标记旧设备为 revoked
      oldDev.status = REVOKED;
      oldDev.ban_reason = "换机检测到倒卖风险";
      await kv.set(oldKey, oldDev);
      return json({ error: "新设备历史异常，疑似倒卖" }, 403);
    }
  }

  // 执行换机
  const now = nowISO();
  const newTransferCount = oldDev.transfer_count + 1;

  oldDev.status = REVOKED;
  oldDev.ban_reason = `换机-旧设备拉黑 (#${newTransferCount})`;

  let updatedNewDev: Device;
  if (newRec.value) {
    updatedNewDev = { ...newRec.value };
    updatedNewDev.status = ACTIVE;
    updatedNewDev.transfer_count = newTransferCount;
    updatedNewDev.last_transfer_at = now;
    updatedNewDev.hwid_history = [...newRec.value!.hwid_history, old_fp];
    updatedNewDev.activated_at = updatedNewDev.activated_at || now;
    updatedNewDev.last_seen = now;
  } else {
    updatedNewDev = {
      ...oldDev,
      fp: new_fp,
      board: body.new_board || "",
      cpu: body.new_cpu || "",
      status: ACTIVE,
      transfer_count: newTransferCount,
      last_transfer_at: now,
      hwid_history: [old_fp],
      created_at: now,
      last_seen: now,
    };
  }

  const txRes = await kv.atomic()
    .check({ key: oldKey, versionstamp: oldRec.versionstamp })
    .check({ key: newKey, versionstamp: newRec.versionstamp })
    .set(oldKey, oldDev)
    .set(newKey, updatedNewDev)
    .commit();

  if (!txRes.ok) return json({ error: "并发冲突，请重试" }, 409);

  return json({ status: "ok", transfer_count: newTransferCount, remaining: TRANSFER_LIMIT - newTransferCount });
}

/* ==================== /admin/revoke ==================== */
async function handleRevoke(req: Request): Promise<Response> {
  let body: any;
  try { body = await req.json(); } catch { return json({ error: "invalid json" }, 400); }

  const fp: string = body.fp || "";
  const device_code: string = body.device_code || "";
  const reason: string = body.reason || "管理员手动拉黑";

  let targetFp = fp;
  if (!fp && device_code) {
    const fpRes = await kv.get<string>(["device_code", device_code]);
    if (!fpRes.value) return json({ error: "设备码不存在" }, 404);
    targetFp = fpRes.value;
  }

  const devKey = ["device", targetFp];
  const devRec = await kv.get<Device>(devKey);
  if (!devRec.value) return json({ error: "设备不存在" }, 404);

  devRec.value.status = REVOKED;
  devRec.value.ban_reason = reason;

  await kv.set(devKey, devRec.value);
  return json({ status: "ok", fp: targetFp });
}

/* ==================== /admin/list ==================== */
async function handleList(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const status = url.searchParams.get("status");
  const limit = parseInt(url.searchParams.get("limit") || "50");

  const devices: Device[] = [];
  const iter = kv.list<Device>({ prefix: ["device"] });
  for await (const entry of iter) {
    if (!status || entry.value.status === status) {
      devices.push(entry.value);
    }
    if (devices.length >= limit) break;
  }

  return json({ count: devices.length, devices });
}

/* ==================== 路由 ==================== */
serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // CORS
  if (method === "OPTIONS") {
    return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST,GET,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" } });
  }

  if (method === "POST" && path === "/license/check") return handleCheck(req);
  if (method === "GET" && path === "/admin/pending") return handlePending(req);
  if (method === "POST" && path === "/admin/activate") return handleActivate(req);
  if (method === "POST" && path === "/admin/replace") return handleReplace(req);
  if (method === "POST" && path === "/admin/revoke") return handleRevoke(req);
  if (method === "GET" && path === "/admin/list") return handleList(req);

  return json({ error: "not found", paths: ["POST /license/check", "GET /admin/pending", "POST /admin/activate", "POST /admin/replace", "POST /admin/revoke", "GET /admin/list"] }, 404);
});

console.log("F210 Auth Server v2.0 running");