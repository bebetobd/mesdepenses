const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const sql = neon(process.env.DATABASE_URL || "postgresql://x:x@localhost/x");
const SECRET = process.env.JWT_SECRET;
const CATS = ["Alimentation","Transport","Logement","Santé","Loisirs","Factures","Fournitures","Voyages","Salaires","Autre"];
const STAT = ["En attente","Approuvée","Remboursée","Rejetée"];
const CURS = ["XOF","EUR","USD"];
const EMAIL = /^\S+@\S+\.\S+$/;

let ready;
const init = () => ready || (ready = (async () => {
  await sql`CREATE TABLE IF NOT EXISTS orgs(id serial PRIMARY KEY, name text NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS users(id serial PRIMARY KEY, org_id int REFERENCES orgs(id) ON DELETE CASCADE, name text NOT NULL, email text UNIQUE NOT NULL, hash text NOT NULL, role text NOT NULL, cur text NOT NULL DEFAULT 'XOF', budget float8 NOT NULL DEFAULT 0)`;
  await sql`CREATE TABLE IF NOT EXISTS pending(email text PRIMARY KEY, name text NOT NULL, company text NOT NULL DEFAULT '', ent boolean NOT NULL, cur text NOT NULL, hash text NOT NULL, code_hash text NOT NULL, expires float8 NOT NULL, attempts int NOT NULL DEFAULT 0, last_sent float8 NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS expenses(id serial PRIMARY KEY, user_id int NOT NULL REFERENCES users(id) ON DELETE CASCADE, org_id int, d text NOT NULL, label text NOT NULL, amount float8 NOT NULL, cat text NOT NULL, note text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'En attente')`;
  await sql`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS receipt text`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now()`;
  await sql`ALTER TABLE users ADD COLUMN IF NOT EXISTS fails int NOT NULL DEFAULT 0, ADD COLUMN IF NOT EXISTS locked_until float8 NOT NULL DEFAULT 0, ADD COLUMN IF NOT EXISTS suspended boolean NOT NULL DEFAULT false, ADD COLUMN IF NOT EXISTS tv int NOT NULL DEFAULT 0`;
  await sql`CREATE TABLE IF NOT EXISTS resets(email text PRIMARY KEY, code_hash text NOT NULL, expires float8 NOT NULL, attempts int NOT NULL DEFAULT 0, last_sent float8 NOT NULL)`;
  await sql`CREATE TABLE IF NOT EXISTS logs(id serial PRIMARY KEY, at timestamptz NOT NULL DEFAULT now(), actor text NOT NULL, action text NOT NULL)`;
})());

const err = (res, code, msg) => res.status(code).json({ error: msg });
const sign = (id, tv = 0) => jwt.sign({ id, tv }, SECRET, { expiresIn: "30d" });
const log = (actor, action) => sql`INSERT INTO logs(actor,action) VALUES(${actor},${action})`.catch(() => {});

async function auth(req) {
  try {
    const { id, tv } = jwt.verify((req.headers.authorization || "").slice(7), SECRET);
    const r = await sql`SELECT u.id,u.org_id,u.name,u.email,u.role,u.cur,u.budget,o.name AS company,u.tv,u.suspended FROM users u LEFT JOIN orgs o ON o.id=u.org_id WHERE u.id=${id}`;
    const u = r[0];
    return u && !u.suspended && (tv || 0) === u.tv ? u : null;
  } catch (e) { return null; }
}

const codeHash = (email, code) => crypto.createHash("sha256").update(email + ":" + code + ":" + SECRET).digest("hex");
const he = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function sendCode(email, name, code, subject = "Votre code de confirmation MesDépenses") {
  const key = process.env.BREVO_API_KEY, from = process.env.MAIL_FROM;
  if (!key || !from) throw Object.assign(new Error("cfg"), { user: "Envoi d’e-mails non configuré (BREVO_API_KEY, MAIL_FROM)." });
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": key, "Content-Type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender: { name: process.env.MAIL_FROM_NAME || "MesDépenses", email: from },
      to: [{ email, name }],
      subject,
      htmlContent: `<p>Bonjour ${he(name)},</p><p>Votre code de confirmation est :</p><p style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</p><p>Il est valable 10 minutes. Si vous n’êtes pas à l’origine de cette demande, ignorez ce message.</p>`,
    }),
  });
  if (!r.ok) {
    console.error("Brevo", r.status, await r.text());
    throw Object.assign(new Error("mail"), { user: "Impossible d’envoyer l’e-mail pour le moment. Vérifiez la configuration Brevo." });
  }
}

async function startVerification(p, res) {
  const old = (await sql`SELECT last_sent FROM pending WHERE email=${p.email}`)[0];
  if (old && Date.now() - old.last_sent < 60000) return err(res, 429, "Patientez une minute avant de demander un nouveau code.");
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const now = Date.now();
  await sql`INSERT INTO pending(email,name,company,ent,cur,hash,code_hash,expires,attempts,last_sent) VALUES(${p.email},${p.name},${p.company},${p.ent},${p.cur},${p.hash},${codeHash(p.email, code)},${now + 600000},0,${now}) ON CONFLICT (email) DO UPDATE SET name=EXCLUDED.name,company=EXCLUDED.company,ent=EXCLUDED.ent,cur=EXCLUDED.cur,hash=EXCLUDED.hash,code_hash=EXCLUDED.code_hash,expires=EXCLUDED.expires,attempts=0,last_sent=EXCLUDED.last_sent`;
  await sendCode(p.email, p.name, code);
  return res.json({ pending: true });
}

function cleanReceipt(r) {
  if (r === undefined) return undefined;
  if (r === null) return null;
  return typeof r === "string" && r.length < 600000 && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(r) ? r : false;
}

function cleanExpense(b) {
  const o = { d: String(b.d || ""), label: String(b.label || "").trim().slice(0, 120), amount: Number(b.amount), cat: b.cat, note: String(b.note || "").trim().slice(0, 300) };
  if (!/^\d{4}-\d\d-\d\d$/.test(o.d) || !o.label || !(o.amount > 0) || !isFinite(o.amount) || !CATS.includes(o.cat)) return null;
  return o;
}

module.exports = async (req, res) => {
  try {
    if (!process.env.DATABASE_URL || !SECRET) return err(res, 500, "Configuration manquante : DATABASE_URL ou JWT_SECRET.");
    await init();
    const path = new URL(req.url, "http://x").pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
    const [a, b, c, d] = path.split("/");
    const m = req.method;
    const body = req.body && typeof req.body === "object" ? req.body : {};

    // ---------- Authentification ----------
    if (a === "auth" && m === "POST") {
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (b === "signup") {
        const name = String(body.name || "").trim();
        const company = String(body.company || "").trim();
        const ent = body.type === "entreprise";
        if (!name) return err(res, 400, "Entrez votre nom.");
        if (ent && !company) return err(res, 400, "Entrez le nom de l’entreprise.");
        if (!EMAIL.test(email)) return err(res, 400, "Adresse e-mail invalide.");
        if (password.length < 8) return err(res, 400, "Mot de passe : 8 caractères minimum.");
        if ((await sql`SELECT 1 FROM users WHERE email=${email}`).length) return err(res, 409, "Un compte existe déjà avec cet e-mail.");
        const hash = await bcrypt.hash(password, 10);
        const cur = CURS.includes(body.cur) ? body.cur : "XOF";
        if (process.env.REQUIRE_EMAIL_CODE === "1")
          return startVerification({ email, name, company: ent ? company : "", ent, cur, hash }, res);
        // Inscription directe (code e-mail désactivé)
        let org = null;
        if (ent) org = (await sql`INSERT INTO orgs(name) VALUES(${company}) RETURNING id`)[0].id;
        const u = (await sql`INSERT INTO users(org_id,name,email,hash,role,cur) VALUES(${org},${name},${email},${hash},${ent ? "admin" : "solo"},${cur}) RETURNING id`)[0];
        await log(email, "Inscription");
        return res.json({ token: sign(u.id) });
      }
      if (b === "verify") {
        const p = (await sql`SELECT * FROM pending WHERE email=${email}`)[0];
        if (!p) return err(res, 400, "Aucune inscription en attente. Recommencez.");
        if (Date.now() > p.expires) return err(res, 400, "Code expiré. Demandez un nouveau code.");
        if (p.attempts >= 5) return err(res, 429, "Trop d’essais. Demandez un nouveau code.");
        if (codeHash(email, String(body.code || "").trim()) !== p.code_hash) {
          await sql`UPDATE pending SET attempts=attempts+1 WHERE email=${email}`;
          return err(res, 400, "Code incorrect.");
        }
        if ((await sql`SELECT 1 FROM users WHERE email=${email}`).length) {
          await sql`DELETE FROM pending WHERE email=${email}`;
          return err(res, 409, "Un compte existe déjà avec cet e-mail.");
        }
        let org = null;
        if (p.ent) org = (await sql`INSERT INTO orgs(name) VALUES(${p.company}) RETURNING id`)[0].id;
        const u = (await sql`INSERT INTO users(org_id,name,email,hash,role,cur) VALUES(${org},${p.name},${email},${p.hash},${p.ent ? "admin" : "solo"},${p.cur}) RETURNING id`)[0];
        await sql`DELETE FROM pending WHERE email=${email}`;
        await log(email, "Inscription");
        return res.json({ token: sign(u.id) });
      }
      if (b === "resend") {
        const p = (await sql`SELECT * FROM pending WHERE email=${email}`)[0];
        if (!p) return err(res, 400, "Aucune inscription en attente. Recommencez.");
        return startVerification({ email, name: p.name, company: p.company, ent: p.ent, cur: p.cur, hash: p.hash }, res);
      }
      if (b === "forgot") {
        const u = (await sql`SELECT name FROM users WHERE email=${email}`)[0];
        const old = (await sql`SELECT last_sent FROM resets WHERE email=${email}`)[0];
        if (u && !(old && Date.now() - old.last_sent < 60000)) {
          const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0"), now = Date.now();
          await sql`INSERT INTO resets(email,code_hash,expires,attempts,last_sent) VALUES(${email},${codeHash(email, code)},${now + 600000},0,${now}) ON CONFLICT (email) DO UPDATE SET code_hash=EXCLUDED.code_hash,expires=EXCLUDED.expires,attempts=0,last_sent=EXCLUDED.last_sent`;
          await sendCode(email, u.name, code, "Réinitialisation de votre mot de passe MesDépenses");
        }
        return res.json({ ok: true });
      }
      if (b === "reset") {
        const r = (await sql`SELECT * FROM resets WHERE email=${email}`)[0];
        if (!r || Date.now() > r.expires || r.attempts >= 5) return err(res, 400, "Code expiré ou invalide. Redemandez un code.");
        if (codeHash(email, String(body.code || "").trim()) !== r.code_hash) {
          await sql`UPDATE resets SET attempts=attempts+1 WHERE email=${email}`;
          return err(res, 400, "Code incorrect.");
        }
        if (password.length < 8) return err(res, 400, "Mot de passe : 8 caractères minimum.");
        await sql`UPDATE users SET hash=${await bcrypt.hash(password, 10)},tv=tv+1,fails=0,locked_until=0 WHERE email=${email}`;
        await sql`DELETE FROM resets WHERE email=${email}`;
        await log(email, "Mot de passe réinitialisé par e-mail");
        return res.json({ ok: true });
      }
      if (b === "login") {
        const u = (await sql`SELECT id,hash,tv,suspended,fails,locked_until FROM users WHERE email=${email}`)[0];
        if (u && u.locked_until > Date.now()) return err(res, 429, "Trop de tentatives. Réessayez dans quelques minutes.");
        if (!u || !(await bcrypt.compare(password, u.hash))) {
          if (u) {
            const f = u.fails + 1;
            await sql`UPDATE users SET fails=${f >= 5 ? 0 : f},locked_until=${f >= 5 ? Date.now() + 900000 : 0} WHERE id=${u.id}`;
            if (f >= 5) await log(email, "Compte verrouillé 15 min (5 échecs de connexion)");
          }
          return err(res, 401, "E-mail ou mot de passe incorrect.");
        }
        if (u.suspended) return err(res, 403, "Ce compte est suspendu. Contactez l’administrateur du service.");
        if (u.fails) await sql`UPDATE users SET fails=0 WHERE id=${u.id}`;
        return res.json({ token: sign(u.id, u.tv) });
      }
      return err(res, 404, "Introuvable");
    }

    // ---------- Routes protégées ----------
    const me = await auth(req);
    if (!me) return err(res, 401, "Non connecté");
    const admin = me.role === "admin";
    const sa = !!process.env.SUPERADMIN_EMAIL && me.email === process.env.SUPERADMIN_EMAIL.trim().toLowerCase();

    if (a === "admin") {
      if (!sa) return err(res, 403, "Réservé au super administrateur.");
      if (b === "overview" && m === "GET") {
        const users = await sql`SELECT u.id,u.name,u.email,u.role,u.cur,u.org_id,o.name AS company,u.suspended,to_char(u.created_at,'DD/MM/YYYY') AS created,(SELECT count(*) FROM expenses e WHERE e.user_id=u.id)::int AS nb,(SELECT coalesce(sum(e.amount),0) FROM expenses e WHERE e.user_id=u.id)::float8 AS total FROM users u LEFT JOIN orgs o ON o.id=u.org_id ORDER BY u.id DESC`;
        const orgs = (await sql`SELECT count(*)::int AS n FROM orgs`)[0].n;
        const expenses = (await sql`SELECT count(*)::int AS n FROM expenses`)[0].n;
        const orgList = await sql`SELECT o.id,o.name,(SELECT count(*) FROM users u WHERE u.org_id=o.id)::int AS members,(SELECT count(*) FROM expenses e WHERE e.org_id=o.id)::int AS nb,(SELECT coalesce(sum(e.amount),0) FROM expenses e WHERE e.org_id=o.id)::float8 AS total,(SELECT cur FROM users u WHERE u.org_id=o.id AND u.role='admin' LIMIT 1) AS cur FROM orgs o ORDER BY o.id DESC`;
        const weeks = await sql`SELECT to_char(wk,'DD/MM') AS w, n FROM (SELECT date_trunc('week',created_at) AS wk, count(*)::int AS n FROM users GROUP BY 1) t ORDER BY wk DESC LIMIT 8`;
        const logs = await sql`SELECT to_char(at,'DD/MM HH24:MI') AS t, actor, action FROM logs ORDER BY id DESC LIMIT 100`;
        return res.json({ users, orgs: orgList, weeks, logs, stats: { users: users.length, solo: users.filter((u) => !u.org_id).length, orgs, expenses } });
      }
      if (b === "backup" && m === "GET") {
        await log(me.email, "Sauvegarde téléchargée");
        return res.json({
          date: new Date().toISOString(),
          orgs: await sql`SELECT * FROM orgs`,
          users: await sql`SELECT id,org_id,name,email,hash,role,cur,budget,created_at FROM users`,
          expenses: await sql`SELECT id,user_id,org_id,d,label,amount,cat,note,status FROM expenses`,
        });
      }
      const id = parseInt(c, 10);
      if (!id) return err(res, 404, "Introuvable");
      if (b === "users" && m === "PUT" && d === "password") {
        const pw = String(body.password || "");
        if (pw.length < 8) return err(res, 400, "Mot de passe : 8 caractères minimum.");
        const r = await sql`UPDATE users SET hash=${await bcrypt.hash(pw, 10)},tv=tv+1 WHERE id=${id} RETURNING id`;
        await log(me.email, "Mot de passe réinitialisé pour le compte #" + id);
        return r.length ? res.json({ ok: true }) : err(res, 404, "Utilisateur introuvable.");
      }
      if (b === "users" && m === "PUT" && d === "suspend") {
        if (id === me.id) return err(res, 400, "Action impossible sur votre propre compte.");
        const s = !!body.suspended;
        await sql`UPDATE users SET suspended=${s},tv=tv+1 WHERE id=${id}`;
        await log(me.email, (s ? "Compte suspendu #" : "Compte réactivé #") + id);
        return res.json({ ok: true });
      }
      if (b === "users" && m === "DELETE") {
        if (id === me.id) return err(res, 400, "Vous ne pouvez pas supprimer votre propre compte.");
        await sql`DELETE FROM users WHERE id=${id}`;
        await log(me.email, "Compte supprimé #" + id);
        return res.json({ ok: true });
      }
      if (b === "orgs" && m === "DELETE") {
        if (id === me.org_id) return err(res, 400, "Vous ne pouvez pas supprimer votre propre entreprise.");
        await sql`DELETE FROM orgs WHERE id=${id}`;
        await log(me.email, "Entreprise supprimée #" + id);
        return res.json({ ok: true });
      }
      return err(res, 404, "Introuvable");
    }

    if (a === "data" && m === "GET") {
      const expenses = admin
        ? await sql`SELECT e.id,e.user_id,e.d,e.label,e.amount,e.cat,e.note,e.status,(e.receipt IS NOT NULL) AS rc,u.name AS who FROM expenses e JOIN users u ON u.id=e.user_id WHERE e.org_id=${me.org_id} ORDER BY e.d DESC, e.id DESC`
        : await sql`SELECT e.id,e.user_id,e.d,e.label,e.amount,e.cat,e.note,e.status,(e.receipt IS NOT NULL) AS rc,u.name AS who FROM expenses e JOIN users u ON u.id=e.user_id WHERE e.user_id=${me.id} ORDER BY e.d DESC, e.id DESC`;
      const members = admin ? await sql`SELECT id,name,email,role FROM users WHERE org_id=${me.org_id} ORDER BY id` : [];
      return res.json({ me: { ...me, sa }, expenses, members });
    }

    if (a === "password" && m === "PUT") {
      const row = (await sql`SELECT hash FROM users WHERE id=${me.id}`)[0];
      if (!(await bcrypt.compare(String(body.old || ""), row.hash))) return err(res, 400, "Mot de passe actuel incorrect.");
      const pw = String(body.password || "");
      if (pw.length < 8) return err(res, 400, "Mot de passe : 8 caractères minimum.");
      const t = (await sql`UPDATE users SET hash=${await bcrypt.hash(pw, 10)},tv=tv+1 WHERE id=${me.id} RETURNING tv`)[0].tv;
      await log(me.email, "Mot de passe modifié");
      return res.json({ ok: true, token: sign(me.id, t) });
    }

    if (a === "budget" && m === "PUT") {
      const v = Math.max(0, Number(body.budget) || 0);
      await sql`UPDATE users SET budget=${v} WHERE id=${me.id}`;
      return res.json({ ok: true });
    }

    if (a === "expenses") {
      const rc = cleanReceipt(body.receipt);
      if (rc === false) return err(res, 400, "Photo invalide ou trop lourde.");
      if (m === "POST" && !b) {
        const o = cleanExpense(body);
        if (!o) return err(res, 400, "Date, libellé, catégorie et montant positif obligatoires.");
        await sql`INSERT INTO expenses(user_id,org_id,d,label,amount,cat,note,receipt) VALUES(${me.id},${me.org_id},${o.d},${o.label},${o.amount},${o.cat},${o.note},${rc || null})`;
        return res.json({ ok: true });
      }
      const id = parseInt(b, 10);
      if (!id) return err(res, 404, "Introuvable");
      const e = (await sql`SELECT * FROM expenses WHERE id=${id}`)[0];
      if (!e) return err(res, 404, "Dépense introuvable.");
      if (c === "status" && m === "PUT") {
        if (!admin || e.org_id !== me.org_id) return err(res, 403, "Réservé à l’administrateur.");
        if (!STAT.includes(body.status)) return err(res, 400, "Statut invalide.");
        await sql`UPDATE expenses SET status=${body.status} WHERE id=${id}`;
        return res.json({ ok: true });
      }
      if (c === "receipt" && m === "GET") {
        if (e.user_id !== me.id && !(admin && e.org_id === me.org_id)) return err(res, 403, "Accès refusé.");
        return e.receipt ? res.json({ receipt: e.receipt }) : err(res, 404, "Aucun reçu.");
      }
      const mine = e.user_id === me.id && (me.role !== "member" || e.status === "En attente");
      if (m === "PUT") {
        if (!mine) return err(res, 403, "Modification non autorisée.");
        const o = cleanExpense(body);
        if (!o) return err(res, 400, "Données invalides.");
        await sql`UPDATE expenses SET d=${o.d},label=${o.label},amount=${o.amount},cat=${o.cat},note=${o.note} WHERE id=${id}`;
        if (rc !== undefined) await sql`UPDATE expenses SET receipt=${rc} WHERE id=${id}`;
        return res.json({ ok: true });
      }
      if (m === "DELETE") {
        if (!mine && !(admin && e.org_id === me.org_id)) return err(res, 403, "Suppression non autorisée.");
        await sql`DELETE FROM expenses WHERE id=${id}`;
        return res.json({ ok: true });
      }
    }

    if (a === "members") {
      if (!admin) return err(res, 403, "Réservé à l’administrateur.");
      if (m === "POST") {
        const name = String(body.name || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        if (!name || !EMAIL.test(email)) return err(res, 400, "Nom ou e-mail invalide.");
        if (password.length < 8) return err(res, 400, "Mot de passe : 8 caractères minimum.");
        if ((await sql`SELECT 1 FROM users WHERE email=${email}`).length) return err(res, 409, "Cet e-mail est déjà utilisé.");
        const hash = await bcrypt.hash(password, 10);
        await sql`INSERT INTO users(org_id,name,email,hash,role,cur) VALUES(${me.org_id},${name},${email},${hash},'member',${me.cur})`;
        return res.json({ ok: true });
      }
      if (m === "PUT" && c === "password") {
        const id = parseInt(b, 10), pw = String(body.password || "");
        if (!id || pw.length < 8) return err(res, 400, "Mot de passe : 8 caractères minimum.");
        const r = await sql`UPDATE users SET hash=${await bcrypt.hash(pw, 10)},tv=tv+1 WHERE id=${id} AND org_id=${me.org_id} AND role='member' RETURNING id`;
        return r.length ? res.json({ ok: true }) : err(res, 404, "Employé introuvable.");
      }
      if (m === "DELETE") {
        const id = parseInt(b, 10);
        if (!id || id === me.id) return err(res, 400, "Action impossible.");
        await sql`DELETE FROM users WHERE id=${id} AND org_id=${me.org_id}`;
        return res.json({ ok: true });
      }
    }
    return err(res, 404, "Introuvable");
  } catch (e) {
    if (e.user) return err(res, 502, e.user);
    ready = null;
    console.error(e);
    return err(res, 500, "Erreur serveur. Vérifiez la configuration (DATABASE_URL).");
  }
};
