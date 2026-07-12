import { DurableObject } from "cloudflare:workers";

const encoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extraHeaders },
  });
}

function cors(request, env) {
  const requested = request.headers.get("Origin") || "";
  const allowed = env.PAGES_ORIGIN || "https://k-ui2.pages.dev";
  const origin = requested === allowed ? allowed : "null";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
  };
}

async function sha256(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function hmac(keyHex, text) {
  if (!/^[0-9a-f]{64}$/i.test(keyHex || "")) return "";
  const bytes = new Uint8Array(keyHex.match(/.{2}/g).map(value => parseInt(value, 16)));
  const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(text));
  return Array.from(new Uint8Array(signature), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function verifyUser(header, env) {
  try {
    const parts = String(header || "").split(".");
    if (parts.length !== 3) return null;
    const [encodedUser, timestamp, signature] = parts;
    const numericTimestamp = Number(timestamp);
    if (!Number.isFinite(numericTimestamp) || Math.abs(Date.now() - numericTimestamp) > 300000) return null;
    const username = atob(encodedUser);
    const admin = env.ADMIN_USERNAME || "admin";
    let keyHex;
    if (username === admin) {
      if (!env.ADMIN_PASSWORD) return null;
      keyHex = await sha256(env.ADMIN_PASSWORD);
    }
    else {
      const user = await env.DB.prepare("SELECT password FROM users WHERE username = ? AND enable = 1").bind(username).first();
      if (!user) return null;
      keyHex = user.password;
    }
    return (await hmac(keyHex, username + timestamp)) === signature ? username : null;
  } catch {
    return null;
  }
}

async function verifyAgent(header, ip, env) {
  if (!header || !ip) return false;
  const server = await env.DB.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
  return !!server?.agent_token && header === server.agent_token;
}

function doRequest(path, request, headers = {}) {
  const outgoing = new Request(`https://durable.internal${path}`, request);
  for (const [name, value] of Object.entries(headers)) outgoing.headers.set(name, value);
  return outgoing;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(request, env) });
    if (url.pathname === "/health") return json({ ok: true, service: "kui-realtime", version: 1 }, 200, cors(request, env));

    if (url.pathname === "/agent/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      const ip = url.searchParams.get("ip") || "";
      const role = url.searchParams.get("role") || "";
      if (!['core', 'proxy'].includes(role)) return json({ error: "Invalid role" }, 400);
      if (!(await verifyAgent(request.headers.get("Authorization"), ip, env))) return json({ error: "Unauthorized" }, 401);
      const stub = env.VPS_PRESENCE.get(env.VPS_PRESENCE.idFromName(ip));
      return stub.fetch(doRequest("/ws", request, { "X-KUI-IP": ip, "X-KUI-ROLE": role }));
    }

    if (url.pathname === "/dashboard/ticket" && request.method === "POST") {
      const username = await verifyUser(request.headers.get("Authorization"), env);
      if (username !== (env.ADMIN_USERNAME || "admin")) return json({ error: "Forbidden" }, 403, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/ticket", { method: "POST", headers: { "X-KUI-USER": username } }));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/dashboard/ws") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "WebSocket required" }, 426);
      if (request.headers.get("Origin") !== (env.PAGES_ORIGIN || "https://k-ui2.pages.dev")) return json({ error: "Forbidden origin" }, 403);
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      return hub.fetch(doRequest(`/ws?ticket=${encodeURIComponent(url.searchParams.get("ticket") || "")}`, request));
    }

    if (url.pathname === "/dashboard/snapshot") {
      if ((await verifyUser(request.headers.get("Authorization"), env)) !== (env.ADMIN_USERNAME || "admin")) return json({ error: "Forbidden" }, 403, cors(request, env));
      const hub = env.DASHBOARD_HUB.get(env.DASHBOARD_HUB.idFromName("main"));
      const response = await hub.fetch(new Request("https://hub.internal/snapshot"));
      return new Response(response.body, { status: response.status, headers: { ...Object.fromEntries(response.headers), ...cors(request, env) } });
    }

    if (url.pathname === "/notify" && request.method === "POST") {
      const username = await verifyUser(request.headers.get("Authorization"), env);
      if (username !== (env.ADMIN_USERNAME || "admin")) return json({ error: "Forbidden" }, 403, cors(request, env));
      const body = await request.json().catch(() => ({}));
      const ips = body.ip ? [body.ip] : (await env.DB.prepare("SELECT ip FROM servers").all()).results.map(row => row.ip);
      await Promise.all(ips.slice(0, 100).map(ip => {
        const stub = env.VPS_PRESENCE.get(env.VPS_PRESENCE.idFromName(ip));
        return stub.fetch(new Request("https://presence.internal/notify", { method: "POST" }));
      }));
      return json({ success: true, notified: ips.length }, 200, cors(request, env));
    }

    return json({ error: "Not found" }, 404, cors(request, env));
  },
};

export class VpsPresence extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    this.snapshot = { ip: "", core: null, proxy: null, updated_at: 0 };
    this.dashboardActive = false;
    this.lastForwarded = 0;
    try { ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong")); } catch {}
    this.lastSeq = { core: -1, proxy: -1 };
    this.bootId = { core: "", proxy: "" };
    this.lastPersisted = 0;
    ctx.blockConcurrencyWhile(async () => {
      this.snapshot = (await ctx.storage.get("snapshot")) || this.snapshot;
      this.lastSeq = (await ctx.storage.get("lastSeq")) || this.lastSeq;
      this.bootId = (await ctx.storage.get("bootId")) || this.bootId;
      this.dashboardActive = (await ctx.storage.get("dashboardActive")) || false;
    });
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/ws") {
      const ip = request.headers.get("X-KUI-IP") || "";
      const role = request.headers.get("X-KUI-ROLE") || "";
      for (const existing of this.ctx.getWebSockets(role)) {
        try { existing.close(1000, "replaced"); } catch {}
      }
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.serializeAttachment({ ip, role, connected_at: Date.now() });
      this.ctx.acceptWebSocket(server, [role]);
      const hub = this.env.DASHBOARD_HUB.get(this.env.DASHBOARD_HUB.idFromName("main"));
      try {
        const activeResponse = await hub.fetch(new Request("https://hub.internal/active"));
        this.dashboardActive = activeResponse.ok && (await activeResponse.json()).active === true;
      } catch {}
      this.snapshot.ip = ip;
      this.snapshot[`${role}_connected`] = true;
      this.snapshot[`${role}_connected_at`] = Date.now();
      await this.persistAndBroadcast();
      server.send(JSON.stringify({ type: "hello.ok", ts: Date.now(), role }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/notify") {
      for (const ws of this.ctx.getWebSockets()) {
        try { ws.send(JSON.stringify({ type: "config.refresh", ts: Date.now() })); } catch {}
      }
      return json({ success: true });
    }
    if (url.pathname === "/dashboard-active" && request.method === "POST") {
      this.dashboardActive = request.headers.get("X-KUI-Active") === "1";
      await this.ctx.storage.put("dashboardActive", this.dashboardActive);
      return json({ success: true });
    }
    if (url.pathname === "/snapshot") return json(this.publicSnapshot());
    return json({ error: "Not found" }, 404);
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > 1024 * 1024) return;
    let envelope;
    try { envelope = JSON.parse(message); } catch { return; }
    const attachment = ws.deserializeAttachment();
    const role = attachment?.role;
    if (!['core', 'proxy'].includes(role) || envelope.role !== role || envelope.ip !== attachment.ip) return;
    const sequence = Number(envelope.seq);
    const bootId = String(envelope.boot_id || "");
    const messageType = String(envelope.type || "status");
    if (!Number.isSafeInteger(sequence) || sequence < 0 || !bootId) return;
    if (this.bootId[role] !== bootId) {
      this.bootId[role] = bootId;
      this.lastSeq[role] = -1;
    }
    if (sequence <= this.lastSeq[role]) return;
    this.lastSeq[role] = sequence;
    if (messageType === "hello") {
      this.snapshot[`${role}_capabilities`] = Array.isArray(envelope.data?.capabilities) ? envelope.data.capabilities.slice(0, 20) : [];
      await this.ctx.storage.put({ lastSeq: this.lastSeq, bootId: this.bootId });
      return;
    }
    if (messageType === "config.result") {
      this.snapshot[`${role}_config_result`] = envelope.data || {};
      this.snapshot[`${role}_config_result_at`] = Date.now();
      await this.persistAndBroadcast();
      return;
    }
    if (messageType !== "status") return;
    const previousRoleState = this.snapshot[role];
    const nextRoleState = envelope.data || {};
    const criticalChange = !previousRoleState || (role === "proxy" && JSON.stringify((previousRoleState.details || []).map(item => [item.tunnel, item.active, item.node_ip])) !== JSON.stringify((nextRoleState.details || []).map(item => [item.tunnel, item.active, item.node_ip])));
    this.snapshot.ip = attachment.ip;
    this.snapshot[role] = nextRoleState;
    this.snapshot[`${role}_connected`] = true;
    this.snapshot[`${role}_last_seen`] = Date.now();
    this.snapshot.updated_at = Date.now();
    if (Date.now() - this.lastPersisted >= 60000) {
      this.lastPersisted = Date.now();
      await this.ctx.storage.put({ snapshot: this.snapshot, lastSeq: this.lastSeq, bootId: this.bootId });
    }
    if (criticalChange || Date.now() - this.lastForwarded >= 5000) await this.broadcast();
  }

  async webSocketClose(ws) {
    await this.markDisconnected(ws);
  }

  async webSocketError(ws) {
    await this.markDisconnected(ws);
  }

  async markDisconnected(ws) {
    const role = ws.deserializeAttachment()?.role;
    if (['core', 'proxy'].includes(role) && this.ctx.getWebSockets(role).length === 0) {
      this.snapshot[`${role}_connected`] = false;
      this.snapshot[`${role}_disconnected_at`] = Date.now();
      await this.persistAndBroadcast();
    }
  }

  publicSnapshot() {
    const now = Date.now();
    const coreAge = this.snapshot.core_last_seen ? now - this.snapshot.core_last_seen : null;
    const proxyAge = this.snapshot.proxy_last_seen ? now - this.snapshot.proxy_last_seen : null;
    return {
      ...this.snapshot,
      core_state: !this.snapshot.core_connected ? "offline" : coreAge > 20000 ? "stale" : "online",
      proxy_state: !this.snapshot.proxy_connected ? "offline" : proxyAge > 20000 ? "stale" : "online",
      core_age: coreAge,
      proxy_age: proxyAge,
      boot_id: this.bootId,
      sequence: this.lastSeq,
    };
  }

  async persistAndBroadcast() {
    this.snapshot.updated_at = Date.now();
    await this.ctx.storage.put("snapshot", this.snapshot);
    await this.broadcast();
  }

  async broadcast() {
    if (!this.dashboardActive) return;
    this.lastForwarded = Date.now();
    const hub = this.env.DASHBOARD_HUB.get(this.env.DASHBOARD_HUB.idFromName("main"));
    await hub.fetch(new Request("https://hub.internal/update", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-KUI-Presence": "1" },
      body: JSON.stringify(this.publicSnapshot()),
    }));
  }
}

export class DashboardHub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    try { ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong")); } catch {}
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/ticket" && request.method === "POST") {
      const ticket = crypto.randomUUID();
      await this.ctx.storage.put(`ticket:${ticket}`, { user: request.headers.get("X-KUI-USER") || "", expires: Date.now() + 60000 });
      return json({ ticket, expires_in: 60 });
    }
    if (url.pathname === "/active") return json({ active: this.ctx.getWebSockets("dashboard").length > 0 });
    if (url.pathname === "/ws") {
      const ticket = url.searchParams.get("ticket") || "";
      const record = await this.ctx.storage.get(`ticket:${ticket}`);
      if (!record || record.expires < Date.now()) {
        if (record) await this.ctx.storage.delete(`ticket:${ticket}`);
        return json({ error: "Invalid ticket" }, 401);
      }
      await this.ctx.storage.delete(`ticket:${ticket}`);
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.serializeAttachment({ user: record.user, connected_at: Date.now() });
      this.ctx.acceptWebSocket(server, ["dashboard"]);
      await this.setDashboardActivity(true);
      server.send(JSON.stringify({ type: "snapshot", data: await this.snapshot(), ts: Date.now() }));
      return new Response(null, { status: 101, webSocket: client });
    }
    if (url.pathname === "/update" && request.method === "POST") {
      if (request.headers.get("X-KUI-Presence") !== "1") return json({ error: "Forbidden" }, 403);
      const snapshot = await request.json();
      if (!snapshot.ip) return json({ error: "Invalid snapshot" }, 400);
      await this.ctx.storage.put(`vps:${snapshot.ip}`, snapshot);
      const payload = JSON.stringify({ type: "patch", data: snapshot, ts: Date.now() });
      for (const ws of this.ctx.getWebSockets("dashboard")) {
        try { ws.send(payload); } catch {}
      }
      return json({ success: true });
    }
    if (url.pathname === "/snapshot") return json(await this.snapshot());
    return json({ error: "Not found" }, 404);
  }

  async snapshot() {
    const servers = (await this.env.DB.prepare("SELECT ip, cpu, mem, disk, load, uptime, net_in_speed, net_out_speed, tcp_conn, udp_conn, last_report FROM servers").all()).results || [];
    const proxies = (await this.env.DB.prepare("SELECT ip, details, last_seen FROM proxy_ctrl_servers").all()).results || [];
    const proxyMap = new Map(proxies.map(row => [row.ip, row]));
    const snapshots = await Promise.all(servers.slice(0, 100).map(async row => {
      const { ip } = row;
      const presence = this.env.VPS_PRESENCE.get(this.env.VPS_PRESENCE.idFromName(ip));
      const response = await presence.fetch(new Request("https://presence.internal/snapshot"));
      const live = response.ok ? await response.json() : null;
      if (live?.ip && (live.core || live.proxy)) return live;
      const proxy = proxyMap.get(ip);
      let details = [];
      try { details = JSON.parse(proxy?.details || "[]"); } catch {}
      return {
        ip,
        transport: "http",
        core: { cpu: row.cpu, mem: row.mem, disk: row.disk, load: row.load, uptime: row.uptime, net_in_speed: row.net_in_speed, net_out_speed: row.net_out_speed, tcp_conn: row.tcp_conn, udp_conn: row.udp_conn },
        core_last_seen: row.last_report || 0,
        core_state: Date.now() - (row.last_report || 0) < 360000 ? "online" : "offline",
        proxy: proxy ? { details } : null,
        proxy_last_seen: proxy?.last_seen || 0,
        proxy_state: proxy && Date.now() - proxy.last_seen < 360000 ? "online" : "offline",
        updated_at: Math.max(row.last_report || 0, proxy?.last_seen || 0),
      };
    }));
    return snapshots.filter(Boolean);
  }

  async webSocketMessage(ws, message) {
    if (message === "ping") {
      ws.send("pong");
      return;
    }
    try {
      const parsed = JSON.parse(message);
      if (parsed?.type === "resync") ws.send(JSON.stringify({ type: "snapshot", data: await this.snapshot(), ts: Date.now() }));
    } catch {}
  }

  async webSocketClose() {
    if (this.ctx.getWebSockets("dashboard").length === 0) await this.setDashboardActivity(false);
  }
  async webSocketError() {
    if (this.ctx.getWebSockets("dashboard").length === 0) await this.setDashboardActivity(false);
  }

  async setDashboardActivity(active) {
    const servers = (await this.env.DB.prepare("SELECT ip FROM servers").all()).results || [];
    await Promise.all(servers.slice(0, 100).map(({ ip }) => {
      const presence = this.env.VPS_PRESENCE.get(this.env.VPS_PRESENCE.idFromName(ip));
      return presence.fetch(new Request("https://presence.internal/dashboard-active", { method: "POST", headers: { "X-KUI-Active": active ? "1" : "0" } }));
    }));
  }
}
