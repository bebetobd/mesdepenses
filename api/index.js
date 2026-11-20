const { neon } = require("@neondatabase/serverless");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

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
  await sql`CREATE TABLE IF NOT EXISTS expenses(id serial PRIMARY KEY, user_id int NOT NULL REFERENCES users(id) ON DELETE CASCADE, org_id int, d text NOT NULL, label text NOT NULL, amount float8 NOT NULL, cat text NOT NULL, note text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'En attente')`;
})());

const err = (res, code, msg) => res.status(code).json({ error: msg });
const sign = (id) => jwt.sign({ id }, SECRET, { expiresIn: "30d" });

async function auth(req) {
  try {
    const { id } = jwt.verify((req.headers.authorization || "").slice(7), SECRET);
    const r = await sql`SELECT u.id,u.org_id,u.name,u.email,u.role,u.cur,u.budget,o.name AS company FROM users u LEFT JOIN orgs o ON o.id=u.org_id WHERE u.id=${id}`;
    return r[0] || null;
  } catch (e) { return null; }
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
    const [a, b, c] = path.split("/");
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
        let org = null;
        if (ent) org = (await sql`INSERT INTO orgs(name) VALUES(${company}) RETURNING id`)[0].id;
        const cur = CURS.includes(body.cur) ? body.cur : "XOF";
        const u = (await sql`INSERT INTO users(org_id,name,email,hash,role,cur) VALUES(${org},${name},${email},${hash},${ent ? "admin" : "solo"},${cur}) RETURNING id`)[0];
        return res.json({ token: sign(u.id) });
      }
      if (b === "login") {
        const u = (await sql`SELECT id,hash FROM users WHERE email=${email}`)[0];
        if (!u || !(await bcrypt.compare(password, u.hash))) return err(res, 401, "E-mail ou mot de passe incorrect.");
        return res.json({ token: sign(u.id) });
      }
      return err(res, 404, "Introuvable");
    }

    // ---------- Routes protégées ----------
    const me = await auth(req);
    if (!me) return err(res, 401, "Non connecté");
    const admin = me.role === "admin";

    if (a === "data" && m === "GET") {
      const expenses = admin
        ? await sql`SELECT e.id,e.user_id,e.d,e.label,e.amount,e.cat,e.note,e.status,u.name AS who FROM expenses e JOIN users u ON u.id=e.user_id WHERE e.org_id=${me.org_id} ORDER BY e.d DESC, e.id DESC`
        : await sql`SELECT e.id,e.user_id,e.d,e.label,e.amount,e.cat,e.note,e.status,u.name AS who FROM expenses e JOIN users u ON u.id=e.user_id WHERE e.user_id=${me.id} ORDER BY e.d DESC, e.id DESC`;
      const members = admin ? await sql`SELECT id,name,email,role FROM users WHERE org_id=${me.org_id} ORDER BY id` : [];
      return res.json({ me, expenses, members });
    }

    if (a === "budget" && m === "PUT") {
      const v = Math.max(0, Number(body.budget) || 0);
      await sql`UPDATE users SET budget=${v} WHERE id=${me.id}`;
      return res.json({ ok: true });
    }

    if (a === "expenses") {
      if (m === "POST" && !b) {
        const o = cleanExpense(body);
        if (!o) return err(res, 400, "Date, libellé, catégorie et montant positif obligatoires.");
        await sql`INSERT INTO expenses(user_id,org_id,d,label,amount,cat,note) VALUES(${me.id},${me.org_id},${o.d},${o.label},${o.amount},${o.cat},${o.note})`;
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
      const mine = e.user_id === me.id && (me.role !== "member" || e.status === "En attente");
      if (m === "PUT") {
        if (!mine) return err(res, 403, "Modification non autorisée.");
        const o = cleanExpense(body);
        if (!o) return err(res, 400, "Données invalides.");
        await sql`UPDATE expenses SET d=${o.d},label=${o.label},amount=${o.amount},cat=${o.cat},note=${o.note} WHERE id=${id}`;
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
      if (m === "DELETE") {
        const id = parseInt(b, 10);
        if (!id || id === me.id) return err(res, 400, "Action impossible.");
        await sql`DELETE FROM users WHERE id=${id} AND org_id=${me.org_id}`;
        return res.json({ ok: true });
      }
    }
    return err(res, 404, "Introuvable");
  } catch (e) {
    ready = null;
    console.error(e);
    return err(res, 500, "Erreur serveur. Vérifiez la configuration (DATABASE_URL).");
  }
};
