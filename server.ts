// ============================================================
// F210 Auth Server v2.4.1
// 使用方法：只改最下面"配置区"的3个值，其余不要动
// 部署：git push 后 Deno Deploy 自动部署
// ============================================================

// ==================== 配置区（只改这里） ====================
const DLL_HASH_WHITELIST: string[] = [
    "5A8DF37F",          // ← 改成你 DLL 的 CRC32
    // 可以填多个，每行一个，用引号包住，逗号结尾
    // 调试期留空数组 [] 表示不校验
];

const ADMIN_SECRET = "xK9#mP2$vL7@qW3!nR5&jY8";  // ← 改成你自己的密码

const MAX_TRANSFER_COUNT = 3;       // 最大换机次数，不用改
const TRANSFER_COOLDOWN_DAYS = 7;   // 换机冷却天数，不用改
// ============================================================



// ==================== 以下全部不用改 ====================

const kv = await Deno.openKv();

// ---------- 工具函数 ----------
function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
    });
}

function adminOk(req: Request): boolean {
    const auth = req.headers.get("authorization");
    return auth === `Bearer ${ADMIN_SECRET}`;
}

// ---------- /license/check ----------
async function checkLicense(req: Request): Promise<Response> {
    let body: any;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }

    const fp = body?.fp;
    const device_code = body?.device_code;
    const dll_hash = body?.dll_hash;

    if (!fp) return json({ error: "missing fp" }, 400);

    // dll_hash 校验
    if (DLL_HASH_WHITELIST.length > 0 && dll_hash) {
        if (!DLL_HASH_WHITELIST.includes(dll_hash)) {
            return json({ status: "rejected", reason: "invalid_dll" }, 403);
        }
    }

    const devKey = ["device", fp];
    const existing = await kv.get(devKey);

    if (existing.value) {
        const dev = existing.value as any;
        if (dev.status === "banned") return json({ status: "banned" }, 403);
        if (dev.status === "active") {
            await kv.set(devKey, { ...dev, last_seen_at: Date.now() });
            return json({ status: "ok", fp, device_code: dev.device_code ?? null });
        }
        return json({ status: "not_authorized", fp, device_code: dev.device_code ?? null });
    }

    // 新设备，原子写入防并发
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

    const atom = kv.atomic().check({ key: devKey, versionstamp: null }).set(devKey, newDev);
    if (device_code) atom.set(["device_code", device_code], fp);
    await atom.commit();

    return json({ status: "not_authorized", fp, device_code });
}

// ---------- 管理接口 ----------
async function adminPending(req: Request): Promise<Response> {
    if (!adminOk(req)) return json({ error: "unauthorized" }, 401);
    const url = new URL(req.url);
    const code = url.searchParams.get("code");

    if (code) {
        const fpEntry = await kv.get(["device_code", code]);
        if (!fpEntry.value) return json({ error: "not found" }, 404);
        const dev = await kv.get(["device", fpEntry.value as string]);
        return json({ device_code: code, fp: fpEntry.value, device: dev.value });
    }

    const list: any[] = [];
    for await (const e of kv.list({ prefix: ["device"] })) {
        const d = e.value as any;
        if (d.status === "initializing" || d.status === "not_authorized") list.push(d);
    }
    return json({ count: list.length, devices: list });
}

async function adminActivate(req: Request): Promise<Response> {
    if (!adminOk(req)) return json({ error: "unauthorized" }, 401);
    let body: any;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }

    let fp = body?.fp;
    const code = body?.device_code;

    if (!fp && code) {
        const e = await kv.get(["device_code", code]);
        if (!e.value) return json({ error: "device_code not found" }, 404);
        fp = e.value as string;
    }
    if (!fp) return json({ error: "missing fp" }, 400);

    const devKey = ["device", fp];
    const existing = await kv.get(devKey);
    if (!existing.value) return json({ error: "device not found" }, 404);

    const dev = existing.value as any;
    await kv.set(devKey, {
        ...dev,
        status: "active",
        activated_at: Date.now(),
        expires_at: body?.expires_at ?? null,
        note: body?.note ?? "",
        contact: body?.contact ?? "",
    });

    return json({ status: "activated", fp, device_code: dev.device_code ?? null });
}

async function adminRevoke(req: Request): Promise<Response> {
    if (!adminOk(req)) return json({ error: "unauthorized" }, 401);
    let body: any;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }
    const fp = body?.fp;
    if (!fp) return json({ error: "missing fp" }, 400);

    const devKey = ["device", fp];
    const existing = await kv.get(devKey);
    if (!existing.value) return json({ error: "not found" }, 404);

    const dev = existing.value as any;
    await kv.set(devKey, { ...dev, status: "banned", banned_at: Date.now(), ban_reason: "revoked" });
    return json({ status: "revoked", fp });
}

async function adminList(req: Request): Promise<Response> {
    if (!adminOk(req)) return json({ error: "unauthorized" }, 401);
    const list: any[] = [];
    for await (const e of kv.list({ prefix: ["device"] })) list.push(e.value);
    return json({ count: list.length, devices: list });
}

async function adminReplace(req: Request): Promise<Response> {
    if (!adminOk(req)) return json({ error: "unauthorized" }, 401);
    let body: any;
    try { body = await req.json(); } catch { return json({ error: "bad json" }, 400); }

    const old_fp = body?.old_fp;
    const new_fp = body?.new_fp;
    if (!old_fp || !new_fp) return json({ error: "missing old_fp or new_fp" }, 400);

    const oldKey = ["device", old_fp];
    const oldEntry = await kv.get(oldKey);
    if (!oldEntry.value) return json({ error: "old device not found" }, 404);

    const oldDev = oldEntry.value as any;
    if ((oldDev.transfer_count ?? 0) >= MAX_TRANSFER_COUNT) {
        return json({ error: "max transfer exceeded" }, 403);
    }

    const now = Date.now();
    await kv.atomic()
        .set(oldKey, { ...oldDev, status: "banned", banned_at: now, ban_reason: "transferred" })
        .set(["device", new_fp], {
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
        })
        .commit();

    return json({ status: "replaced", old_fp, new_fp });
}

// ==================== 启动入口（不要改这里） ====================
console.log("F210 Auth Server v2.4.1");
console.log("Listening on http://0.0.0.0:8000/");

Deno.serve(async (req: Request) => {
    const url = new URL(req.url);
    const path = url.pathname;

    // CORS 预检
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
            return await checkLicense(req);
        }
        if (path === "/admin/pending") return await adminPending(req);
        if (path === "/admin/activate" && req.method === "POST") return await adminActivate(req);
        if (path === "/admin/replace" && req.method === "POST") return await adminReplace(req);
        if (path === "/admin/revoke" && req.method === "POST") return await adminRevoke(req);
        if (path === "/admin/list") return await adminList(req);

        return json({ error: "not found", path }, 404);
    } catch (e: any) {
        console.error("Unhandled error:", e);
        return json({ error: "internal", detail: e.message }, 500);
    }
});