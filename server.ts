// server.ts — F210 Auth Server v2.0
// Deno Deploy 入口文件

// ==================== 配置 ====================
const VALID_DLL_HASHES = new Set([
    "5A8DF37F" // 填入你 DLL 的 CRC32，如 "A3F82C1D"
    // 空着则跳过校验（调试期可用）
]);

const ADMIN_KEY = "xK9#mP2$vL7@qW3!nR5&jY8"; // 管理接口密钥，部署后改掉
const MAX_TRANSFER = 3;
const TRANSFER_COOLDOWN_DAYS = 7;

// ==================== KV ====================
const kv = await Deno.openKv();

// ==================== 工具 ====================
function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}

function getClientIp(req: Request): string {
    return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
        ?? req.headers.get("x-real-ip")
        ?? "unknown";
}

// ==================== 路由 ====================
async function handleCheck(req: Request): Promise<Response> {
    if (req.method !== "POST") {
        return jsonResponse({ error: "method not allowed" }, 405);
    }

    let body: any;
    try {
        body = await req.json();
    } catch {
        return jsonResponse({ error: "invalid json" }, 400);
    }

    const fp = body?.fp;
    const device_code = body?.device_code;
    const dll_hash = body?.dll_hash;

    if (!fp) {
        return jsonResponse({ error: "missing fp" }, 400);
    }

    // dll_hash 校验（白名单非空时才校验）
    if (VALID_DLL_HASHES.size > 0 && dll_hash) {
        if (!VALID_DLL_HASHES.has(dll_hash)) {
            return jsonResponse({ status: "rejected", reason: "invalid_dll" }, 403);
        }
    }

    const devKey = ["device", fp];
    const existing = await kv.get(devKey);

    if (existing.value) {
        const dev = existing.value as any;

        if (dev.status === "banned") {
            return jsonResponse({ status: "banned" }, 403);
        }

        if (dev.status === "active") {
            // 更新最后在线时间
            await kv.set(devKey, { ...dev, last_seen_at: Date.now() });
            return jsonResponse({ status: "ok", fp, device_code: dev.device_code ?? null });
        }

        // initializing / expired / other → 仍待授权
        return jsonResponse({ status: "not_authorized", fp, device_code: dev.device_code ?? null });
    }

    // 新设备：原子创建，防并发重复写入
    const newDev: any = {
        fp,
        device_code: device_code ?? null,
        status: "initializing",
        created_at: Date.now(),
        last_seen_at: Date.now(),
        hwid_history: [fp],
        transfer_count: 0,
        note: "",
        contact: "",
    };

    const atomic = kv.atomic()
        .check({ key: devKey, versionstamp: null })
        .set(devKey, newDev);

    // 如果有短码，同时建映射
    if (device_code) {
        atomic.set(["device_code", device_code], fp);
    }

    const result = await atomic.commit();

    if (!result.ok) {
        // 并发冲突，重新读
        const retry = await kv.get(devKey);
        if (retry.value) {
            const dev = retry.value as any;
            return jsonResponse({ status: dev.status === "active" ? "ok" : "not_authorized", fp });
        }
        return jsonResponse({ status: "error", reason: "concurrent_write_failed" }, 500);
    }

    return jsonResponse({ status: "not_authorized", fp, device_code });
}

// ==================== 管理接口（统一鉴权） ====================
function checkAdmin(req: Request): boolean {
    const auth = req.headers.get("authorization");
    return auth === `Bearer ${ADMIN_KEY}`;
}

async function handleAdminPending(req: Request): Promise<Response> {
    if (!checkAdmin(req)) return jsonResponse({ error: "unauthorized" }, 401);

    const url = new URL(req.url);
    const code = url.searchParams.get("code");

    if (code) {
        // 按短码查
        const fpEntry = await kv.get(["device_code", code]);
        if (!fpEntry.value) {
            return jsonResponse({ error: "device_code not found" }, 404);
        }
        const dev = await kv.get(["device", fpEntry.value as string]);
        return jsonResponse({
            device_code: code,
            fp: fpEntry.value,
            device: dev.value ?? null,
        });
    }

    // 列出所有 initializing 设备
    const devices: any[] = [];
    const iter = kv.list({ prefix: ["device"] });
    for await (const entry of iter) {
        const dev = entry.value as any;
        if (dev.status === "initializing" || dev.status === "not_authorized") {
            devices.push(dev);
        }
    }

    return jsonResponse({ count: devices.length, devices });
}

async function handleAdminActivate(req: Request): Promise<Response> {
    if (!checkAdmin(req)) return jsonResponse({ error: "unauthorized" }, 401);
    if (req.method !== "POST") return jsonResponse({ error: "method not allowed" }, 405);

    let body: any;
    try { body = await req.json(); } catch { return jsonResponse({ error: "invalid json" }, 400); }

    let fp = body?.fp;
    const code = body?.device_code;
    const expires_at = body?.expires_at ?? null;
    const note = body?.note ?? "";
    const contact = body?.contact ?? "";

    // 支持用短码反查 fp
    if (!fp && code) {
        const fpEntry = await kv.get(["device_code", code]);
        if (!fpEntry.value) {
            return jsonResponse({ error: "device_code not found" }, 404);
        }
        fp = fpEntry.value as string;
    }

    if (!fp) return jsonResponse({ error: "missing fp or device_code" }, 400);

    const devKey = ["device", fp];
    const existing = await kv.get(devKey);

    if (!existing.value) {
        return jsonResponse({ error: "device not found, ask user to run DLL first" }, 404);
    }

    const dev = existing.value as any;
    const updated = {
        ...dev,
        status: "active",
        activated_at: Date.now(),
        expires_at,
        note,
        contact,
    };

    await kv.set(devKey, updated);

    return jsonResponse({ status: "activated", fp, device_code: dev.device_code ?? null });
}

async function handleAdminReplace(req: Request): Promise<Response> {
    if (!checkAdmin(req)) return jsonResponse({ error: "unauthorized" }, 401);
    if (req.method !== "POST") return jsonResponse({ error: "method not allowed" }, 405);

    let body: any;
    try { body = await req.json(); } catch { return jsonResponse({ error: "invalid json" }, 400); }

    const old_fp = body?.old_fp;
    const new_fp = body?.new_fp;
    if (!old_fp || !new_fp) return jsonResponse({ error: "missing old_fp or new_fp" }, 400);

    const oldKey = ["device", old_fp];
    const oldEntry = await kv.get(oldKey);
    if (!oldEntry.value) return jsonResponse({ error: "old device not found" }, 404);

    const oldDev = oldEntry.value as any;

    // 检查换机次数
    if ((oldDev.transfer_count ?? 0) >= MAX_TRANSFER) {
        return jsonResponse({ error: "max transfer count exceeded" }, 403);
    }

    // 新设备如果存在，检查是否被他人用过
    const newKey = ["device", new_fp];
    const newEntry = await kv.get(newKey);
    if (newEntry.value) {
        const newDev = newEntry.value as any;
        if (newDev.hwid_history && newDev.hwid_history.some((h: string) => h !== new_fp && h !== old_fp)) {
            return jsonResponse({ error: "new device has been used by another user" }, 403);
        }
    }

    // 原子操作：旧设备拉黑 + 新设备激活
    const now = Date.now();
    const updatedOld = { ...oldDev, status: "banned", banned_at: now, ban_reason: "transferred" };
    const newDev: any = {
        fp: new_fp,
        device_code: oldDev.device_code,
        status: "active",
        activated_at: now,
        expires_at: oldDev.expires_at,
        note: oldDev.note,
        contact: oldDev.contact,
        hwid_history: [new_fp],
        transfer_count: 0,
        created_at: now,
        last_seen_at: now,
    };

    await kv.atomic()
        .set(oldKey, updatedOld)
        .set(newKey, newDev)
        .commit();

    return jsonResponse({ status: "replaced", old_fp, new_fp });
}

async function handleAdminRevoke(req: Request): Promise<Response> {
    if (!checkAdmin(req)) return jsonResponse({ error: "unauthorized" }, 401);
    if (req.method !== "POST") return jsonResponse({ error: "method not allowed" }, 405);

    let body: any;
    try { body = await req.json(); } catch { return jsonResponse({ error: "invalid json" }, 400); }

    const fp = body?.fp;
    if (!fp) return jsonResponse({ error: "missing fp" }, 400);

    const devKey = ["device", fp];
    const existing = await kv.get(devKey);
    if (!existing.value) return jsonResponse({ error: "device not found" }, 404);

    const dev = existing.value as any;
    await kv.set(devKey, { ...dev, status: "banned", banned_at: Date.now(), ban_reason: "revoked_by_admin" });

    return jsonResponse({ status: "revoked", fp });
}

async function handleAdminList(req: Request): Promise<Response> {
    if (!checkAdmin(req)) return jsonResponse({ error: "unauthorized" }, 401);

    const devices: any[] = [];
    const iter = kv.list({ prefix: ["device"] });
    for await (const entry of iter) {
        devices.push(entry.value);
    }

    return jsonResponse({ count: devices.length, devices });
}

// ==================== 入口 ====================
Deno.serve(async (req: Request) => {
    const url = new URL(req.url);
    const path = url.pathname;

    // CORS（调试用，生产可删）
    if (req.method === "OPTIONS") {
        return new Response(null, {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
        });
    }

    try {
        if (path === "/license/check" && req.method === "POST") {
            return await handleCheck(req);
        }

        if (path === "/admin/pending") {
            return await handleAdminPending(req);
        }

        if (path === "/admin/activate" && req.method === "POST") {
            return await handleAdminActivate(req);
        }

        if (path === "/admin/replace" && req.method === "POST") {
            return await handleAdminReplace(req);
        }

        if (path === "/admin/revoke" && req.method === "POST") {
            return await handleAdminRevoke(req);
        }

        if (path === "/admin/list") {
            return await handleAdminList(req);
        }

        return jsonResponse({ error: "not found", path }, 404);
    } catch (e: any) {
        return jsonResponse({ error: "internal error", detail: e.message }, 500);
    }
});