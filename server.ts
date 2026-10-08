/**
 * server.ts v2.5.1
 * F210 Auth Server - P1+P2: nonce replay + hardware change detection + ban/unban
 */
const ADMIN_KEY = Deno.env.get("ADMIN_KEY") || "xK9#mP2$vL7@qW3!nR5&jY8";
const KV = await Deno.openKv();

const VALID_CONFIG_HASHES: string[] = [];
const VALID_DLL_CRCS: string[] = [
    "11680216"  // ← 填你新编译的 DLL CRC32
];

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

interface DeviceRecord {
    fp: string;
    device_code: string | null;
    hwid: string;
    status: "initializing" | "pending" | "active" | "hw_changed" | "revoked" | "banned";
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
        board: "", cpu: "",
        cpu_fp: "", board_fp: "",
        config_hash: "", dll_crc: "",
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
            const config_hash = (body.config_hash || "").toUpperCase();
            const dll_crc = (body.dll_crc || "").toUpperCase();
            const version = body.version || "";
            const nonce = body.nonce || "";
            const cpu_fp = body.cpu_fp || "";
            const board_fp = body.board_fp || "";
            const client_ip = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || null;

            if (!fp) {
                return new Response(JSON.stringify({ error: "missing fp/hwid" }), {
                    status: 400, headers: cors_headers()
                });
            }

	    // 👇【推荐】在这里插入请求接收日志
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

            const config_hash_valid = VALID_CONFIG_HASHES.length === 0 || !config_hash || VALID_CONFIG_HASHES.includes(config_hash);
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
                device.cpu_fp = cpu_fp;
                device.board_fp = board_fp;
                device.config_hash = config_hash;
                device.dll_crc = dll_crc;
                device.current_version = version;
                device.last_ip = client_ip;
                device.total_requests = 1;
                device.config_hash_valid = config_hash_valid;
                device.dll_crc_valid = dll_crc_valid;
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

            if (!dll_crc_valid) {
                const old_note = device.note ? device.note + " | " : "";
                device.note = old_note + `Invalid DLL CRC: ${dll_crc} at ${now}`;
            }

            // ★ P2: 硬件变更检测（仅对 active 设备生效）
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
                    await KV.set(key, device);
                    return new Response(JSON.stringify({
                        status: "hw_changed",
                        device_code: device.device_code,
                        message: "Hardware change detected, re-verification required"
                    }), { status: 202, headers: cors_headers() });
                }
            }

            // 非 active 设备也保存新指纹（便于换机后重新审批继续检测）
            if (!device.cpu_fp && cpu_fp) device.cpu_fp = cpu_fp;
            if (!device.board_fp && board_fp) device.board_fp = board_fp;

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
            } else if (device.status === "hw_changed") {
                await KV.set(key, device);
                return new Response(JSON.stringify({
                    status: "hw_changed", device_code: device.device_code, message: "Hardware change detected, awaiting admin re-verification"
                }), { status: 202, headers: cors_headers() });
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
    // 语义：退款/授权到期/换机超限 → 软撤销，后续可重新 approve 恢复
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

    // ============ ★ /admin/ban ============
    // 语义：检测到破解/作弊/黑产 → 封禁，需要 unban 才能恢复
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

    // ============ ★ /admin/unban ============
    // 语义：解除封禁 → 回到 pending，需要用户重新走审批（或管理员直接 approve）
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
            if (device.status !== "banned") {
                return new Response(JSON.stringify({ error: "device is not banned", current_status: device.status }), { status: 400, headers: cors_headers() });
            }
            // unban 后回到 pending，让管理员决定是 approve 还是让用户重新走流程
            device.status = "pending";
            const old_note = device.note ? device.note + " | " : "";
            device.note = old_note + `Unbanned at ${now_str()}`;
            await KV.set(key, device);
            return new Response(JSON.stringify({ success: true, fp: device.fp, status: device.status, message: "Device unbanned, back to pending" }), { headers: cors_headers() });
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
            version: "2.5.1",
            description: "F210 Device Record Schema",
            fields: Object.keys(sample).map(k => ({ field: k, type: typeof (sample as any)[k], sample: (sample as any)[k] }))
        }, null, 2), { headers: cors_headers() });
    }

    // ============ /health ============
    if (path === "/health" && method === "GET") {
        return new Response(JSON.stringify({ status: "ok", version: "2.5.1", time: now_str() }), { headers: cors_headers() });
    }

    return new Response(JSON.stringify({ error: "not found", path }), { status: 404, headers: cors_headers() });
}

console.log(`F210 Auth Server v2.5.1 starting...`);
Deno.serve({ port: 8000 }, handler);