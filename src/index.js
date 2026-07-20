export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- Login ---
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { code } = await request.json().catch(() => ({}));
      if (!code || code !== env.ADMIN_CODE) {
        return Response.json({ ok: false }, { status: 401 });
      }
      const exp = Date.now() + 2 * 60 * 60 * 1000;
      const sig = await hmac(String(exp), env.SESSION_SECRET);
      return Response.json({ ok: true }, {
        headers: {
          "Set-Cookie": `adminSession=${exp}.${sig}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=7200`
        }
      });
    }

    // --- Bild hochladen ---
    if (url.pathname === "/api/upload" && request.method === "POST") {
      if (!(await isAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const { code, name, data, thumb } = await request.json().catch(() => ({}));
      if (!code || !data) {
        return Response.json({ error: "missing" }, { status: 400 });
      }
      const key = code.toUpperCase();
      if (await env.IMAGES.get(key)) {
        return Response.json({ error: "exists" }, { status: 409 });
      }
      await env.IMAGES.put(key, JSON.stringify({
        name: name || "image",
        data,
        created: new Date().toISOString()
      }));
      if (thumb) {
        await env.IMAGES.put("thumb:" + key, thumb);
      }
      return Response.json({ ok: true });
    }

    // --- Liste aller Codes ---
    if (url.pathname === "/api/images" && request.method === "GET") {
      if (!(await isAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const list = await env.IMAGES.list();
      const keys = list.keys
        .map(k => k.name)
        .filter(n => !n.startsWith("thumb:"));
      return Response.json({ keys });
    }

    // --- Vorschaubild ---
    if (url.pathname === "/api/thumb" && request.method === "GET") {
      if (!(await isAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const code = (url.searchParams.get("code") || "").toUpperCase();
      const thumb = await env.IMAGES.get("thumb:" + code);
      if (!thumb) return Response.json({ error: "notfound" }, { status: 404 });
      return Response.json({ ok: true, thumb });
    }

    // --- Bild löschen ---
    if (url.pathname === "/api/delete" && request.method === "POST") {
      if (!(await isAdmin(request, env))) {
        return Response.json({ error: "unauthorized" }, { status: 401 });
      }
      const { code } = await request.json().catch(() => ({}));
      if (code) {
        const key = code.toUpperCase();
        await env.IMAGES.delete(key);
        await env.IMAGES.delete("thumb:" + key);
      }
      return Response.json({ ok: true });
    }

    // --- Bild per Code abrufen (öffentlich) ---
    if (url.pathname === "/api/picture" && request.method === "POST") {
      const { code } = await request.json().catch(() => ({}));
      if (!code) return Response.json({ error: "missing" }, { status: 400 });
      const key = code.toUpperCase();
      if (key.startsWith("THUMB:")) {
        return Response.json({ error: "notfound" }, { status: 404 });
      }
      const raw = await env.IMAGES.get(key);
      if (!raw) return Response.json({ error: "notfound" }, { status: 404 });
      const entry = JSON.parse(raw);
      return Response.json({ ok: true, name: entry.name, data: entry.data });
    }

    // --- Dashboard schützen ---
    if (url.pathname.startsWith("/admindashboard")) {
      if (!(await isAdmin(request, env))) {
        return Response.redirect(new URL("/admin/", request.url).toString(), 302);
      }
    }

    return env.ASSETS.fetch(request);
  }
};

async function isAdmin(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/adminSession=([^;]+)/);
  if (!match) return false;
  return verify(match[1], env.SESSION_SECRET);
}

async function hmac(data, secret) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const buf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verify(token, secret) {
  const [exp, sig] = token.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return sig === await hmac(exp, secret);
}
