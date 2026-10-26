const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const initSqlJs = require("sql.js");
const app = express();
const PORT = process.env.PORT || 3000;
const DATA = path.join(__dirname, "data");
const DBFILE = path.join(DATA, "facebreak.db");
fs.mkdirSync(DATA, { recursive: true });
let db;
const terminalActionLocks = new Map();
const IDENTIFICATION_COOLDOWN_MS = 30000;
function createDb(SQL) {
  const bytes = fs.existsSync(DBFILE) ? fs.readFileSync(DBFILE) : null;
  return bytes ? new SQL.Database(bytes) : new SQL.Database();
}
function wrapDb(raw) {
  const save = () => fs.writeFileSync(DBFILE, Buffer.from(raw.export()));
  return {
    exec(sql) {
      raw.run(sql);
      save();
    },
    prepare(sql) {
      return {
        get(...p) {
          const s = raw.prepare(sql);
          try {
            s.bind(p);
            return s.step() ? s.getAsObject() : undefined;
          } finally {
            s.free();
          }
        },
        all(...p) {
          const s = raw.prepare(sql),
            o = [];
          try {
            s.bind(p);
            while (s.step()) o.push(s.getAsObject());
            return o;
          } finally {
            s.free();
          }
        },
        run(...p) {
          const s = raw.prepare(sql);
          try {
            s.bind(p);
            s.step();
          } finally {
            s.free();
          }
          save();
          const q = raw.exec("SELECT last_insert_rowid() AS id");
          return { lastInsertRowid: q[0]?.values?.[0]?.[0] ?? 0 };
        },
      };
    },
  };
}
function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return salt + ":" + crypto.scryptSync(password, salt, 64).toString("hex");
}
function verifyPassword(password, stored) {
  try {
    const [salt, hex] = String(stored).split(":");
    if (!salt || !hex) return false;
    const a = crypto.scryptSync(password, salt, 64);
    const b = Buffer.from(hex, "hex");
    return b.length === a.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
async function init() {
  const SQL = await initSqlJs({
    locateFile: (f) =>
      path.join(__dirname, "node_modules", "sql.js", "dist", f),
  });
  db = wrapDb(createDb(SQL));
  db.exec(
    `CREATE TABLE IF NOT EXISTS admin_users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Ativo');CREATE TABLE IF NOT EXISTS profiles(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE);CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,profile_id INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'Ativo',FOREIGN KEY(profile_id) REFERENCES profiles(id));CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));CREATE TABLE IF NOT EXISTS sectors(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,work_minutes INTEGER NOT NULL DEFAULT 100,break_minutes INTEGER NOT NULL DEFAULT 20);CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,cpf TEXT NOT NULL UNIQUE,sector_id INTEGER NOT NULL,activity TEXT,shift TEXT,work_minutes INTEGER NOT NULL DEFAULT 100,break_minutes INTEGER NOT NULL DEFAULT 20,status TEXT NOT NULL DEFAULT 'Ativo',face_descriptor TEXT,face_image TEXT,FOREIGN KEY(sector_id) REFERENCES sectors(id));CREATE TABLE IF NOT EXISTS work_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,employee_id INTEGER NOT NULL,entry_at TEXT NOT NULL,exit_at TEXT,active INTEGER NOT NULL DEFAULT 1,FOREIGN KEY(employee_id) REFERENCES employees(id));CREATE TABLE IF NOT EXISTS breaks(id INTEGER PRIMARY KEY AUTOINCREMENT,session_id INTEGER NOT NULL,sequence INTEGER NOT NULL,start_at TEXT NOT NULL,end_at TEXT,duration_seconds INTEGER,minimum_seconds INTEGER NOT NULL,compliance TEXT,FOREIGN KEY(session_id) REFERENCES work_sessions(id));CREATE TABLE IF NOT EXISTS justifications(id INTEGER PRIMARY KEY AUTOINCREMENT,employee_id INTEGER NOT NULL,type TEXT NOT NULL,text TEXT NOT NULL,date TEXT NOT NULL,user_id INTEGER,FOREIGN KEY(employee_id) REFERENCES employees(id),FOREIGN KEY(user_id) REFERENCES users(id));CREATE TABLE IF NOT EXISTS occurrences(id INTEGER PRIMARY KEY AUTOINCREMENT,employee_id INTEGER NOT NULL,break_id INTEGER NOT NULL,type TEXT NOT NULL,date TEXT NOT NULL,UNIQUE(break_id,type),FOREIGN KEY(employee_id) REFERENCES employees(id),FOREIGN KEY(break_id) REFERENCES breaks(id));`,
  );
  try {
    db.exec("ALTER TABLE employees ADD COLUMN face_image TEXT");
  } catch (e) {}
  db.exec(
    `INSERT OR IGNORE INTO profiles(name) VALUES ('Administrador');INSERT OR IGNORE INTO profiles(name) VALUES ('Gerente');`,
  );
  const old = db
    .prepare("SELECT name,email,password_hash,status FROM admin_users LIMIT 1")
    .get?.();
  if (
    old &&
    !db
      .prepare("SELECT 1 FROM users WHERE lower(email)=lower(?)")
      .get(old.email)
  ) {
    const pid = db
      .prepare("SELECT id FROM profiles WHERE name='Administrador'")
      .get().id;
    db.prepare(
      "INSERT INTO users(name,email,password_hash,profile_id,status) VALUES(?,?,?,?,?)",
    ).run(old.name, old.email, old.password_hash, pid, old.status || "Ativo");
  }
  if (
    !db
      .prepare("SELECT 1 FROM users WHERE lower(email)=lower(?)")
      .get("admin@facebreak.com")
  ) {
    const pid = db
      .prepare("SELECT id FROM profiles WHERE name='Administrador'")
      .get().id;
    db.prepare(
      "INSERT INTO users(name,email,password_hash,profile_id,status) VALUES(?,?,?,?,?)",
    ).run(
      "Administrador",
      "admin@facebreak.com",
      hashPassword("Admin@123"),
      pid,
      "Ativo",
    );
  }
  if (
    !db
      .prepare("SELECT 1 FROM users WHERE lower(email)=lower(?)")
      .get("gerente@facebreak.com")
  ) {
    const pid = db
      .prepare("SELECT id FROM profiles WHERE name='Gerente'")
      .get().id;
    db.prepare(
      "INSERT INTO users(name,email,password_hash,profile_id,status) VALUES(?,?,?,?,?)",
    ).run(
      "Gerente",
      "gerente@facebreak.com",
      hashPassword("Gerente@123"),
      pid,
      "Ativo",
    );
  }
  if (!db.prepare("SELECT COUNT(*) c FROM sectors").get().c)
    for (const s of [
      ["Desossa", 100, 20],
      ["Embalagem", 100, 20],
      ["Abate", 100, 20],
    ])
      db.prepare(
        "INSERT INTO sectors(name,work_minutes,break_minutes) VALUES(?,?,?)",
      ).run(...s);
}
function cookies(req) {
  const o = {};
  for (const p of String(req.headers.cookie || "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0)
      o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  }
  return o;
}
function auth(req) {
  const token = cookies(req).facebreak_sid;
  if (!token) return null;
  const h = crypto.createHash("sha256").update(token).digest("hex");
  const s = db
    .prepare(
      'SELECT s.user_id,u.name,u.email,u.status,p.name profile FROM sessions s JOIN users u ON u.id=s.user_id JOIN profiles p ON p.id=u.profile_id WHERE s.id=? AND s.expires_at>? AND u.status="Ativo"',
    )
    .get(h, Date.now());
  return s ? { ...s, token } : null;
}
function requireAuth(req, res, next) {
  const u = auth(req);
  if (!u)
    return res
      .status(401)
      .json({ error: "Sessão administrativa expirada. Faça login novamente." });
  req.user = u;
  next();
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.profile))
      return res
        .status(403)
        .json({ error: "Você não tem permissão para esta ação." });
    next();
  };
}
function jsonUser(u) {
  return {
    id: u.user_id || u.id,
    name: u.name,
    email: u.email,
    profile: u.profile || u.profile_name,
    status: u.status,
  };
}
init()
  .then(() => {
    app.use(express.json({ limit: "2mb" }));
    app.use(express.static(path.join(__dirname, "public"), { index: false }));
    app.get("/", (req, res) =>
      res.redirect(auth(req) ? "/manager.html" : "/login"),
    );
    app.get("/login", (req, res) => {
      if (auth(req)) return res.redirect("/manager.html");
      res.sendFile(path.join(__dirname, "public", "login.html"));
    });
    app.get("/manager.html", (req, res) => {
      if (!auth(req)) return res.redirect("/login");
      res.sendFile(path.join(__dirname, "public", "manager.html"));
    });
    app.get("/terminal", (req, res) =>
      res.sendFile(path.join(__dirname, "public", "terminal.html")),
    );
    app.post("/api/auth/login", (req, res) => {
      const email = String(req.body.email || "").trim();
      const password = String(req.body.password || "");
      const u = db
        .prepare(
          "SELECT u.*,p.name profile FROM users u JOIN profiles p ON p.id=u.profile_id WHERE lower(u.email)=lower(?)",
        )
        .get(email);
      if (
        !u ||
        u.status !== "Ativo" ||
        !verifyPassword(password, u.password_hash)
      )
        return res.status(401).json({ error: "E-mail ou senha incorretos." });
      const token = crypto.randomBytes(32).toString("hex");
      const h = crypto.createHash("sha256").update(token).digest("hex");
      db.prepare(
        "INSERT INTO sessions(id,user_id,expires_at) VALUES(?,?,?)",
      ).run(h, u.id, Date.now() + 8 * 60 * 60 * 1000);
      res.setHeader(
        "Set-Cookie",
        `facebreak_sid=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=28800`,
      );
      res.json({
        ok: true,
        user: { id: u.id, name: u.name, email: u.email, profile: u.profile },
      });
    });
    app.post("/api/auth/logout", (req, res) => {
      const t = cookies(req).facebreak_sid;
      if (t)
        db.prepare("DELETE FROM sessions WHERE id=?").run(
          crypto.createHash("sha256").update(t).digest("hex"),
        );
      res.setHeader(
        "Set-Cookie",
        "facebreak_sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax",
      );
      res.json({ ok: true });
    });
    app.get("/api/auth/me", (req, res) => {
      const u = auth(req);
      if (!u) return res.status(401).json({ error: "Não autenticado." });
      res.json({ user: jsonUser(u) });
    });
    app.use("/api", (req, res, next) => {
      const publicApi =
        req.path === "/face/recognize" ||
        req.path === "/attendance/action" ||
        req.path === "/terminal/active" ||
        (req.path.startsWith("/employees/") && req.method === "GET");
      if (publicApi) return next();
      requireAuth(req, res, next);
    });
    const sectorName = (id) =>
      db.prepare("SELECT name FROM sectors WHERE id=?").get(id)?.name || "";
    const current = (id) => {
      const s = db
        .prepare(
          "SELECT * FROM work_sessions WHERE employee_id=? AND active=1 ORDER BY id DESC LIMIT 1",
        )
        .get(id);
      if (!s) return null;
      const b = db
        .prepare(
          "SELECT * FROM breaks WHERE session_id=? ORDER BY sequence DESC LIMIT 1",
        )
        .get(s.id);
      return { session: s, break: b };
    };
    app.get("/api/terminal/active", (req, res) => {
      const workers = db
        .prepare(
          'SELECT e.id,e.name,e.work_minutes workMinutes,e.break_minutes breakMinutes,s.name sector FROM employees e JOIN sectors s ON s.id=e.sector_id WHERE e.status=\"Ativo\" ORDER BY e.name',
        )
        .all();
      const active = [];
      const nowMs = Date.now();
      for (const w of workers) {
        const c = current(w.id);
        if (!c) continue;
        const paused = !!(c.break && !c.break.end_at);
        if (paused) {
          const limitSeconds = Math.max(1, Number(w.breakMinutes) || 20) * 60;
          const elapsedSeconds = Math.floor(
            (nowMs - Date.parse(c.break.start_at)) / 1000,
          );
          const remainingSeconds = limitSeconds - elapsedSeconds;
          if (remainingSeconds <= 0) {
            db.prepare(
              "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
            ).run(
              w.id,
              c.break.id,
              "Excesso de pausa",
              new Date(nowMs).toISOString(),
            );
          }
          active.push({
            id: w.id,
            name: w.name,
            sector: w.sector,
            status: remainingSeconds <= 0 ? "Pausa encerrada" : "Em pausa",
            phase: "pause",
            since: c.break.start_at,
            limitSeconds,
            remainingSeconds: Math.max(0, remainingSeconds),
          });
        } else {
          const base = c.break?.end_at || c.session.entry_at;
          const limitSeconds = Math.max(1, Number(w.workMinutes) || 100) * 60;
          const elapsedSeconds = Math.floor((nowMs - Date.parse(base)) / 1000);
          const remainingSeconds = Math.max(0, limitSeconds - elapsedSeconds);
          active.push({
            id: w.id,
            name: w.name,
            sector: w.sector,
            status: "Trabalhando",
            phase: "work",
            since: base,
            limitSeconds,
            remainingSeconds,
          });
        }
      }
      res.json({ count: active.length, workers: active });
    });
    app.get("/api/alerts/recent", (req, res) => {
      const nowMs = Date.now();
      const since = new Date(nowMs - 15 * 60 * 1000).toISOString();
      // Verifica pausas excedidas aqui também, mesmo que o terminal não esteja aberto.
      const activePauses = db.prepare(
        'SELECT e.id employeeId,e.break_minutes breakMinutes FROM employees e WHERE e.status="Ativo"'
      ).all();
      for (const employee of activePauses) {
        const c = current(employee.employeeId);
        if (c && c.break && !c.break.end_at) {
          const elapsed = Math.floor((nowMs - Date.parse(c.break.start_at)) / 1000);
          const allowed = Math.max(1, Number(employee.breakMinutes) || 20) * 60;
          if (elapsed >= allowed) {
            db.prepare(
              "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
            ).run(employee.employeeId, c.break.id, "Excesso de pausa", new Date(nowMs).toISOString());
          }
        }
      }
      const alerts = db.prepare(
        "SELECT o.id,e.name employee,s.name sector,o.date,o.type FROM occurrences o JOIN employees e ON e.id=o.employee_id JOIN sectors s ON s.id=e.sector_id WHERE o.type IN ('Tentativa de retorno durante a pausa','Excesso de pausa') AND o.date>? ORDER BY o.date DESC"
      ).all(since);
      res.json({ alerts });
    });
    app.get("/api/state", (req, res) => {
      const workers = db
        .prepare(
          "SELECT e.id,e.name,e.cpf,e.sector_id sectorId,e.activity,e.shift,e.work_minutes workMinutes,e.break_minutes breakMinutes,e.status,e.face_descriptor faceDescriptor,e.face_image faceImage,s.name sector FROM employees e JOIN sectors s ON s.id=e.sector_id ORDER BY e.name",
        )
        .all()
        .map((w) => ({
          ...w,
          faceDescriptor: w.faceDescriptor
            ? JSON.parse(w.faceDescriptor)
            : null,
          faceImage: w.faceImage || null,
        }));
      const sectors = db
        .prepare(
          "SELECT id,name,work_minutes work,break_minutes breakMinutes FROM sectors ORDER BY name",
        )
        .all();
      const records = {};
      for (const w of workers) {
        const c = current(w.id);
        if (c) {
          const last = db
            .prepare(
              "SELECT end_at FROM breaks WHERE session_id=? AND end_at IS NOT NULL ORDER BY sequence DESC LIMIT 1",
            )
            .get(c.session.id);
          records[w.id] = {
            entry: c.session.entry_at,
            active: !!c.session.active,
            paused: !!(c.break && !c.break.end_at),
            pauseStart: c.break?.start_at || null,
            returnAt: c.break?.end_at || null,
            lastBreakEnd: last?.end_at || null,
          };
        }
      }
      const just = db
        .prepare(
          "SELECT j.*,e.name workerName,u.name userName FROM justifications j JOIN employees e ON e.id=j.employee_id LEFT JOIN users u ON u.id=j.user_id ORDER BY j.id",
        )
        .all();
      res.json({
        workers,
        sectors,
        records,
        justifications: just,
        user: jsonUser(req.user),
      });
    });
    app.get("/api/users", requireRole("Administrador"), (req, res) =>
      res.json({
        users: db
          .prepare(
            "SELECT u.id,u.name,u.email,p.name profile,u.status FROM users u JOIN profiles p ON p.id=u.profile_id ORDER BY u.name",
          )
          .all(),
      }),
    );
    app.post("/api/users", requireRole("Administrador"), (req, res) => {
      const b = req.body;
      if (
        !b.name ||
        !b.email ||
        !b.password ||
        !["Administrador", "Gerente"].includes(b.profile)
      )
        return res
          .status(400)
          .json({ error: "Preencha nome, e-mail, senha e perfil." });
      try {
        const pid = db
          .prepare("SELECT id FROM profiles WHERE name=?")
          .get(b.profile).id;
        const r = db
          .prepare(
            "INSERT INTO users(name,email,password_hash,profile_id,status) VALUES(?,?,?,?,?)",
          )
          .run(
            b.name.trim(),
            b.email.trim().toLowerCase(),
            hashPassword(b.password),
            pid,
            b.status || "Ativo",
          );
        res.json({ id: r.lastInsertRowid });
      } catch (e) {
        res
          .status(400)
          .json({ error: "E-mail já cadastrado ou dados inválidos." });
      }
    });
    app.put("/api/users/:id", requireRole("Administrador"), (req, res) => {
      const b = req.body;
      if (
        !b.name ||
        !b.email ||
        !["Administrador", "Gerente"].includes(b.profile)
      )
        return res.status(400).json({ error: "Dados inválidos." });
      try {
        const pid = db
          .prepare("SELECT id FROM profiles WHERE name=?")
          .get(b.profile).id;
        if (b.password)
          db.prepare(
            "UPDATE users SET name=?,email=?,password_hash=?,profile_id=?,status=? WHERE id=?",
          ).run(
            b.name.trim(),
            b.email.trim().toLowerCase(),
            hashPassword(b.password),
            pid,
            b.status || "Ativo",
            req.params.id,
          );
        else
          db.prepare(
            "UPDATE users SET name=?,email=?,profile_id=?,status=? WHERE id=?",
          ).run(
            b.name.trim(),
            b.email.trim().toLowerCase(),
            pid,
            b.status || "Ativo",
            req.params.id,
          );
        res.json({ ok: true });
      } catch (e) {
        res
          .status(400)
          .json({ error: "Não foi possível atualizar o usuário." });
      }
    });
    app.delete("/api/users/:id", requireRole("Administrador"), (req, res) => {
      if (Number(req.params.id) === Number(req.user.user_id))
        return res
          .status(400)
          .json({
            error:
              "O administrador conectado não pode excluir a própria conta.",
          });
      db.prepare("DELETE FROM sessions WHERE user_id=?").run(req.params.id);
      db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
      res.json({ ok: true });
    });
    function validMinutes(v, def) {
      const n = Number(v);
      return Number.isFinite(n) && n > 0 && n <= 1440 ? Math.round(n) : def;
    }
    app.post("/api/sectors", requireRole("Administrador"), (req, res) => {
      const name = String(req.body.name || "")
        .trim()
        .replace(/\s+/g, " ");
      if (!name)
        return res.status(400).json({ error: "Informe o nome do setor." });
      const work = validMinutes(req.body.work, 100),
        brk = validMinutes(req.body.breakMinutes, 20);
      try {
        const r = db
          .prepare(
            "INSERT INTO sectors(name,work_minutes,break_minutes) VALUES(?,?,?)",
          )
          .run(name, work, brk);
        res.json({ id: r.lastInsertRowid });
      } catch (e) {
        res.status(400).json({ error: "Setor já existe ou é inválido." });
      }
    });
    app.put("/api/sectors/:id", requireRole("Administrador"), (req, res) => {
      const name = String(req.body.name || "")
        .trim()
        .replace(/\s+/g, " ");
      if (!name)
        return res.status(400).json({ error: "Informe o nome do setor." });
      const work = validMinutes(req.body.work, 100),
        brk = validMinutes(req.body.breakMinutes, 20);
      try {
        db.prepare(
          "UPDATE sectors SET name=?,work_minutes=?,break_minutes=? WHERE id=?",
        ).run(name, work, brk, req.params.id);
        res.json({ ok: true });
      } catch (e) {
        res
          .status(400)
          .json({
            error: "Não foi possível editar o setor. O nome pode já existir.",
          });
      }
    });
    app.delete("/api/sectors/:id", requireRole("Administrador"), (req, res) => {
      const n = db
        .prepare("SELECT COUNT(*) c FROM employees WHERE sector_id=?")
        .get(req.params.id).c;
      if (n)
        return res
          .status(400)
          .json({
            error: "Não é possível excluir setor com funcionários vinculados.",
          });
      db.prepare("DELETE FROM sectors WHERE id=?").run(req.params.id);
      res.json({ ok: true });
    });
    function validCPF(c) {
      c = String(c || "").replace(/\D/g, "");
      if (!/^\d{11}$/.test(c) || /^([0-9])\1+$/.test(c)) return false;
      let sum = 0;
      for (let i = 0; i < 9; i++) sum += +c[i] * (10 - i);
      let d = (sum * 10) % 11;
      if (d === 10) d = 0;
      if (d !== +c[9]) return false;
      sum = 0;
      for (let i = 0; i < 10; i++) sum += +c[i] * (11 - i);
      d = (sum * 10) % 11;
      if (d === 10) d = 0;
      return d === +c[10];
    }
    function normalizeName(name) {
      return String(name || "")
        .trim()
        .replace(/\s+/g, " ")
        .split(" ")
        .map((p) =>
          p
            ? p.charAt(0).toLocaleUpperCase("pt-BR") +
              p.slice(1).toLocaleLowerCase("pt-BR")
            : "",
        )
        .join(" ");
    }
    function validName(name) {
      return /^[A-Za-zÀ-ÖØ-öø-ÿ]+(?:[ '-][A-Za-zÀ-ÖØ-öø-ÿ]+)*$/.test(
        String(name || "").trim(),
      );
    }
    app.post("/api/employees", requireRole("Administrador"), (req, res) => {
      const b = req.body;
      const name = normalizeName(b.name);
      if (!validName(name))
        return res
          .status(400)
          .json({ error: "O nome deve conter somente letras e espaços." });
      if (!validCPF(b.cpf))
        return res
          .status(400)
          .json({ error: "CPF inválido. Confira os 11 dígitos." });
      if (!Array.isArray(b.faceDescriptor))
        return res
          .status(400)
          .json({ error: "Cadastre a face do funcionário antes de salvar." });
      try {
        const r = db
          .prepare(
            "INSERT INTO employees(name,cpf,sector_id,activity,shift,work_minutes,break_minutes,status,face_descriptor,face_image) VALUES(?,?,?,?,?,?,?,?,?,?)",
          )
          .run(
            name,
            String(b.cpf).replace(/\D/g, ""),
            b.sectorId,
            b.activity,
            b.shift,
            b.workMinutes || 100,
            b.breakMinutes || 20,
            b.status || "Ativo",
            JSON.stringify(b.faceDescriptor),
            b.faceImage || null,
          );
        res.json({ id: r.lastInsertRowid });
      } catch (e) {
        res
          .status(400)
          .json({ error: "CPF já cadastrado ou dados inválidos." });
      }
    });
    app.put("/api/employees/:id", requireRole("Administrador"), (req, res) => {
      const b = req.body;
      const name = normalizeName(b.name);
      if (!validName(name))
        return res
          .status(400)
          .json({ error: "O nome deve conter somente letras e espaços." });
      if (!validCPF(b.cpf))
        return res
          .status(400)
          .json({ error: "CPF inválido. Confira os 11 dígitos." });
      try {
        const cpf = String(b.cpf).replace(/\D/g, "");
        const duplicate = db
          .prepare("SELECT id FROM employees WHERE cpf=? AND id<>?")
          .get(cpf, req.params.id);
        if (duplicate)
          return res
            .status(400)
            .json({ error: "CPF já cadastrado em outro funcionário." });
        if (Array.isArray(b.faceDescriptor)) {
          db.prepare(
            "UPDATE employees SET name=?,cpf=?,sector_id=?,activity=?,shift=?,work_minutes=?,break_minutes=?,status=?,face_descriptor=?,face_image=COALESCE(?,face_image) WHERE id=?",
          ).run(
            name,
            cpf,
            b.sectorId,
            b.activity,
            b.shift,
            b.workMinutes || 100,
            b.breakMinutes || 20,
            b.status || "Ativo",
            JSON.stringify(b.faceDescriptor),
            b.faceImage || null,
            req.params.id,
          );
        } else {
          db.prepare(
            "UPDATE employees SET name=?,cpf=?,sector_id=?,activity=?,shift=?,work_minutes=?,break_minutes=?,status=? WHERE id=?",
          ).run(
            name,
            cpf,
            b.sectorId,
            b.activity,
            b.shift,
            b.workMinutes || 100,
            b.breakMinutes || 20,
            b.status || "Ativo",
            req.params.id,
          );
        }
        res.json({ ok: true });
      } catch (e) {
        res
          .status(400)
          .json({ error: "CPF já cadastrado ou dados inválidos." });
      }
    });
    app.delete(
      "/api/employees/:id",
      requireRole("Administrador"),
      (req, res) => {
        db.prepare(
          "DELETE FROM breaks WHERE session_id IN (SELECT id FROM work_sessions WHERE employee_id=?)",
        ).run(req.params.id);
        db.prepare("DELETE FROM work_sessions WHERE employee_id=?").run(
          req.params.id,
        );
        db.prepare("DELETE FROM justifications WHERE employee_id=?").run(
          req.params.id,
        );
        db.prepare("DELETE FROM occurrences WHERE employee_id=?").run(
          req.params.id,
        );
        db.prepare("DELETE FROM employees WHERE id=?").run(req.params.id);
        res.json({ ok: true });
      },
    );
    app.get("/api/employees/:id/current", (req, res) => {
      const c = current(req.params.id);
      if (!c) return res.json({});
      const e = db
        .prepare(
          "SELECT id,name,sector_id sectorId,work_minutes workMinutes,break_minutes breakMinutes,status FROM employees WHERE id=?",
        )
        .get(req.params.id);
      const last = db
        .prepare(
          "SELECT end_at FROM breaks WHERE session_id=? AND end_at IS NOT NULL ORDER BY sequence DESC LIMIT 1",
        )
        .get(c.session.id);
      const events = [];
      events.push({ label: "Entrada registrada", time: c.session.entry_at });
      for (const b of db
        .prepare(
          "SELECT sequence,start_at,end_at,compliance FROM breaks WHERE session_id=? ORDER BY sequence",
        )
        .all(c.session.id)) {
        events.push({
          label: `Pausa ${b.sequence} iniciada`,
          time: b.start_at,
        });
        if (b.end_at)
          events.push({
            label:
              `Retorno da pausa ${b.sequence} — ${b.compliance || ""}`.trim(),
            time: b.end_at,
          });
      }
      res.json({
        record: {
          entry: c.session.entry_at,
          active: !!c.session.active,
          paused: !!(c.break && !c.break.end_at),
          pauseStart: c.break?.start_at || null,
          returnAt: c.break?.end_at || null,
        },
        break: c.break,
        employee: e,
        lastBreakEnd: last?.end_at || null,
        events,
      });
    });
    app.post("/api/face/recognize", (req, res) => {
      const input = req.body.descriptor;
      if (!Array.isArray(input))
        return res.status(400).json({ error: "Descritor facial inválido." });
      let best = null,
        bestD = Infinity;
      for (const w of db
        .prepare(
          'SELECT e.id,e.name,e.cpf,e.sector_id sectorId,s.name sector,e.activity,e.shift,e.work_minutes workMinutes,e.break_minutes breakMinutes,e.status,e.face_descriptor FROM employees e JOIN sectors s ON s.id=e.sector_id WHERE e.status="Ativo" AND e.face_descriptor IS NOT NULL',
        )
        .all()) {
        const a = JSON.parse(w.face_descriptor);
        let d = 0;
        for (let i = 0; i < Math.min(a.length, input.length); i++) {
          const z = a[i] - input[i];
          d += z * z;
        }
        d = Math.sqrt(d);
        if (d < bestD) {
          bestD = d;
          best = w;
        }
      }
      if (!best || bestD > 0.55)
        return res.status(404).json({ error: "Rosto não reconhecido." });
      best.distance = bestD;
      res.json({ employee: best });
    });
    app.post("/api/attendance/action", (req, res) => {
      const id = Number(req.body.employeeId);
      const nowMs = Date.now();
      const e = db
        .prepare('SELECT * FROM employees WHERE id=? AND status=\"Ativo\"')
        .get(id);
      if (!e)
        return res.status(404).json({ error: "Funcionário não encontrado." });
      const lockedAt = terminalActionLocks.get(id) || 0;
      const remainingMs = IDENTIFICATION_COOLDOWN_MS - (nowMs - lockedAt);
      if (lockedAt && remainingMs > 0) {
        const remainingSeconds = Math.ceil(remainingMs / 1000);
        const c0 = current(id);
        if (c0 && c0.break && !c0.break.end_at)
          db.prepare(
            "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
          ).run(id, c0.break.id, "Tentativa de retorno durante a pausa", new Date(nowMs).toISOString());
        return res
          .status(429)
          .json({
            error: `Aguarde ${remainingSeconds} segundo(s) para uma nova identificação.`,
            cooldownRemainingSeconds: remainingSeconds,
          });
      }
      const now = new Date(nowMs).toISOString();
      let c = current(id);
      if (!c) {
        const r = db
          .prepare(
            "INSERT INTO work_sessions(employee_id,entry_at,active) VALUES(?,?,1)",
          )
          .run(id, now);
        terminalActionLocks.set(id, nowMs);
        return res.json({
          action: "entry",
          label: "Entrada registrada",
          badge: "green-b",
          message: "Entrada registrada com sucesso.",
          sessionId: r.lastInsertRowid,
          cooldownSeconds: 30,
        });
      }
      if (c.break && !c.break.end_at) {
        const dur = Math.max(
          0,
          Math.floor((Date.parse(now) - Date.parse(c.break.start_at)) / 1000),
        );
        const min = Math.max(1, Number(c.break.minimum_seconds) || 1);
        if (dur < min) {
          db.prepare(
            "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
          ).run(id, c.break.id, "Tentativa de retorno durante a pausa", now);
          return res.json({
            action: "blocked",
            label: "Em pausa",
            badge: "yellow-b",
            message: "Retorno bloqueado: a pausa obrigatória ainda não terminou.",
            remainingSeconds: min - dur,
            minimumSeconds: min,
          });
        }
        let compliance = "Cumprida";
        if (dur < min) compliance = "Retorno muito cedo";
        else if (dur > min) compliance = "Retorno tardio";
        db.prepare(
          "UPDATE breaks SET end_at=?,duration_seconds=?,compliance=? WHERE id=?",
        ).run(now, dur, compliance, c.break.id);
        if (compliance !== "Cumprida")
          db.prepare(
            "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
          ).run(id, c.break.id, compliance, new Date(nowMs).toISOString());
        terminalActionLocks.set(id, nowMs);
        return res.json({
          action: "return",
          label: "Trabalhando",
          badge:
            compliance === "Cumprida"
              ? "green-b"
              : compliance === "Retorno muito cedo"
                ? "red-b"
                : "yellow-b",
          message: `Retorno registrado. ${compliance}.`,
          pauseAlert: dur < min,
          remainingSeconds: Math.max(0, min - dur),
          durationSeconds: dur,
          minimumSeconds: min,
          compliance,
          cooldownSeconds: 30,
        });
      }
      const lastBreak = db
        .prepare(
          "SELECT end_at FROM breaks WHERE session_id=? AND end_at IS NOT NULL ORDER BY sequence DESC LIMIT 1",
        )
        .get(c.session.id);
      const base = lastBreak?.end_at || c.session.entry_at;
      const workedSeconds = Math.max(
        0,
        Math.floor((Date.parse(now) - Date.parse(base)) / 1000),
      );
      const requiredWorkSeconds =
        Math.max(1, Number(e.work_minutes) || 100) * 60;
      const sequenceRow = db
        .prepare(
          "SELECT COALESCE(MAX(sequence),0)+1 n FROM breaks WHERE session_id=?",
        )
        .get(c.session.id);
      const seq = sequenceRow.n;
      const breakResult = db
        .prepare(
          "INSERT INTO breaks(session_id,sequence,start_at,minimum_seconds) VALUES(?,?,?,?)",
        )
        .run(
          c.session.id,
          seq,
          now,
          Math.max(1, Number(e.break_minutes) || 20) * 60,
        );
      const breakId = breakResult.lastInsertRowid;
      if (workedSeconds < requiredWorkSeconds) {
        db.prepare(
          "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
        ).run(id, breakId, "Pausa iniciada antecipadamente", now);
      } else if (workedSeconds > requiredWorkSeconds) {
        db.prepare(
          "INSERT OR IGNORE INTO occurrences(employee_id,break_id,type,date) VALUES(?,?,?,?)",
        ).run(id, breakId, "Pausa iniciada tardiamente", now);
      }
      terminalActionLocks.set(id, nowMs);
      const timing =
        workedSeconds < requiredWorkSeconds
          ? "Pausa iniciada antecipadamente"
          : workedSeconds > requiredWorkSeconds
            ? "Pausa iniciada tardiamente"
            : "Pausa iniciada no horário previsto";
      return res.json({
        action: "break_start",
        label: "Em pausa",
        badge: "yellow-b",
        message: `Pausa ${seq} iniciada. ${timing}. Tempo permitido: ${Math.max(1, Number(e.break_minutes) || 20)} minuto(s).`,
        sequence: seq,
        minimumSeconds: Math.max(1, Number(e.break_minutes) || 20) * 60,
        cooldownSeconds: 30,
      });
    });
    app.post(
      "/api/justifications",
      requireRole("Administrador", "Gerente"),
      (req, res) => {
        db.prepare(
          "INSERT INTO justifications(employee_id,type,text,date,user_id) VALUES(?,?,?,?,?)",
        ).run(
          req.body.employeeId,
          req.body.type,
          req.body.text,
          new Date().toISOString(),
          req.user.user_id,
        );
        res.json({ ok: true });
      },
    );
    app.get(
      "/api/reports/json",
      requireRole("Administrador", "Gerente"),
      (req, res) =>
        res.json(
          db
            .prepare(
              "SELECT e.name employee,s.name sector,e.activity,ws.entry_at entry,b.sequence,b.start_at pause_start,b.end_at return_at,b.duration_seconds,b.minimum_seconds,b.compliance FROM breaks b JOIN work_sessions ws ON ws.id=b.session_id JOIN employees e ON e.id=ws.employee_id JOIN sectors s ON s.id=e.sector_id ORDER BY ws.entry_at,b.sequence",
            )
            .all(),
        ),
    );
    app.get(
      "/api/reports/csv",
      requireRole("Administrador", "Gerente"),
      (req, res) => {
        const rows = db
          .prepare(
            "SELECT e.name employee,s.name sector,e.activity,ws.entry_at entry,b.sequence,b.start_at pause_start,b.end_at return_at,b.duration_seconds,b.minimum_seconds,b.compliance FROM breaks b JOIN work_sessions ws ON ws.id=b.session_id JOIN employees e ON e.id=ws.employee_id JOIN sectors s ON s.id=e.sector_id ORDER BY ws.entry_at,b.sequence",
          )
          .all();
        const h = [
          "Funcionário",
          "Setor",
          "Atividade",
          "Entrada",
          "Pausa nº",
          "Início da pausa",
          "Retorno",
          "Duração (min)",
          "Mínimo (min)",
          "Cumprimento",
        ];
        const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
        const lines = [
          h.map(esc).join(";"),
          ...rows.map((r) =>
            [
              r.employee,
              r.sector,
              r.activity,
              r.entry,
              r.sequence,
              r.pause_start,
              r.return_at,
              r.duration_seconds == null
                ? ""
                : Math.round(r.duration_seconds / 60),
              Math.round(r.minimum_seconds / 60),
              r.compliance || "Em andamento",
            ]
              .map(esc)
              .join(";"),
          ),
        ];
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="facebreak_relatorio.csv"',
        );
        res.send("\ufeff" + lines.join("\r\n"));
      },
    );
    app.listen(PORT, () =>
      console.log(`FaceBreak rodando em http://localhost:${PORT}`),
    );
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
