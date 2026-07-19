export default {
  async fetch(request, env) {
    const url = new URL(request.url);

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

    if (url.pathname.startsWith("/admindashboard")) {
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/adminSession=([^;]+)/);

      if (!match || !(await verify(match[1], env.SESSION_SECRET))) {
        return Response.redirect(new URL("/admin/", request.url).toString(), 302);
      }
    }

    return env.ASSETS.fetch(request);
  }
};

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
