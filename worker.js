var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}

var serviceAccount = {
  "type": "service_account",
  "project_id": "[REDACTED_PROJECT_ID]",
  "private_key_id": "[REDACTED_PRIVATE_KEY_ID]",
  "private_key": "[REDACTED_PRIVATE_KEY]",
  "client_email": "[REDACTED_CLIENT_EMAIL]",
  "client_id": "[REDACTED_CLIENT_ID]",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "[REDACTED_CERT_URL]",
  "universe_domain": "googleapis.com"
};

async function getGoogleAuthToken(user, key, scope) {
  function objectToBase64url(object) {
    return arrayBufferToBase64Url(
      new TextEncoder().encode(JSON.stringify(object))
    );
  }
  function arrayBufferToBase64Url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }
  function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
  }
  ;
  async function sign(content, signingKey) {
    const buf = str2ab(content);
    const plainKey = signingKey.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace(/(\r\n|\n|\r)/gm, "");
    const binaryKey = str2ab(atob(plainKey));
    const signer = await crypto.subtle.importKey(
      "pkcs8",
      binaryKey,
      {
        name: "RSASSA-PKCS1-V1_5",
        hash: {
          name: "SHA-256"
        }
      },
      false,
      ["sign"]
    );
    const binarySignature = await crypto.subtle.sign({
      name: "RSASSA-PKCS1-V1_5"
    }, signer, buf);
    return arrayBufferToBase64Url(binarySignature);
  }
  const jwtHeader = objectToBase64url({
    alg: "RS256",
    typ: "JWT"
  });
  try {
    const assertiontime = Math.round(Date.now() / 1e3);
    const expirytime = assertiontime + 3600;
    const claimset = objectToBase64url({
      "iss": user,
      "scope": scope,
      "aud": "https://oauth2.googleapis.com/token",
      "exp": expirytime,
      "iat": assertiontime
    });
    const jwtUnsigned = jwtHeader + "." + claimset;
    const signedJwt = jwtUnsigned + "." + await sign(jwtUnsigned, key);
    const body = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + signedJwt;
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
        "Host": "oauth2.googleapis.com"
      },
      body
    });
    const oauth = await response.json();
    return oauth;
  } catch (err) {
    console.log(err);
  }
}
var src_default = {
  async fetch(request, env, ctx) {
    return handleRequest(request, env);
  }
};
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (path === "/sendData") {
    return handleSendData(request, env);
  } else if (path === "/getLastLocation") {
    return handleLastLocation(request, env);
  } else if (path === "/updateLastLocation") {
    return handleUpdateLastLocation(request, env);
  } else if (path === "/tokenRefresh") {
    return handleTokenChange(request, env);
  } else if (path === "/getToken") {
    return handleGetToken(request, env);
  } else {
    return new Response("Not Found", { status: 404 });
  }
}
async function handleSendData(request, env) {
  const db = env.DB;
  const user = request.headers.get("user");
  const value = request.headers.get("value");
  const apiKey = request.headers.get("apiKey");
  if (apiKey == "[REDACTED_API_KEY_1]") {
    const dataDict = JSON.parse(value);
    const token = await getToken(env);
    const data = `{"message":{"token":"${(await db.prepare("SELECT token FROM tokens WHERE User = ?").bind(user).first())["token"]}","data":${value},"android":{"priority":"high"}}}`;
    const url = "https://fcm.googleapis.com/v1/projects/[REDACTED_PROJECT_ID]/messages:send";
    const headers = { "Authorization": `Bearer ${token}`, "Content-Type": "application/json; UTF-8" };
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: data
    });
    if (dataDict && dataDict["key2"] == "receiveLocation") {
      const updateQuery = "UPDATE FindMyLocations SET Location = ?, timestamp = ? WHERE User = ?";
      await db.prepare(updateQuery).bind(`${dataDict["key3"]},${dataDict["key4"]}`, Date.now(), dataDict["key1"]).run();
      const insertQuery = `INSERT INTO ${dataDict["key1"]} (timestamp, location) VALUES ("${Date.now()}","${dataDict["key3"]},${dataDict["key4"]}")`;
      await db.prepare(insertQuery).run();
    }
    const responseBody = await response.json();
    return new Response(JSON.stringify(responseBody), {
      headers: { "Content-Type": "application/json" },
      status: 200
    });
  }
}
async function handleLastLocation(request, env) {
  const user = request.headers.get("user");
  const apiKey = request.headers.get("apiKey");
  if (apiKey == "[REDACTED_API_KEY_2]") {
    const db = env.DB;
    const query = "SELECT Location,timestamp FROM FindMyLocations WHERE User = ?";
    const result = await db.prepare(query).bind(user).first();
    const loc = result["Location"];
    return new Response(loc, {
      headers: { "Content-Type": "application/json" },
      status: 200
    });
  }
}
async function handleUpdateLastLocation(request, env) {
  const user = request.headers.get("user");
  const apiKey = request.headers.get("apiKey");
  const location = request.headers.get("location");
  if (apiKey == "[REDACTED_API_KEY_3]") {
    const db = env.DB;
    const updateQuery = "UPDATE FindMyLocations SET Location = ?, timestamp = ? WHERE User = ?";
    await db.prepare(updateQuery).bind(location, Date.now(), user).run();
    const insertQuery = `INSERT INTO ${user} (timestamp, location) VALUES ("${Date.now()}","${location}")`;
    await db.prepare(insertQuery).run();
    return new Response("Done", {
      headers: { "Content-Type": "application/json" },
      status: 200
    });
  }
}
async function handleTokenChange(request, env) {
  const db = env.DB;
  try {
    const user = request.headers.get("user");
    const fcmToken = request.headers.get("fcmToken");
    const apiKey = request.headers.get("apiKey");
    if (apiKey == "[REDACTED_API_KEY_4]") {
      const updateQuery = "UPDATE tokens SET token = ? WHERE user = ?";
      await db.prepare(updateQuery).bind(fcmToken, user).run();
      return new Response("Success", {
        headers: { "Content-Type": "application/json" },
        status: 200
      });
    } else {
      return new Response("Invalid API", {
        headers: { "Content-Type": "application/json" },
        status: 200
      });
    }
  } catch (error) {
    return new Response("Invalid JSON", { status: 400 });
  }
}
async function handleGetToken(request, env) {
  try {
    const apiKey = request.headers.get("apiKey");
    if (apiKey == "[REDACTED_API_KEY_5]") {
      const token = await getToken(env);
      return new Response(token, {
        headers: { "Content-Type": "application/json" },
        status: 200
      });
    }
  } catch (error) {
    return new Response("Invalid Request " + error.message, { status: 400 });
  }
}
async function getToken(env) {
  const db = env.DB;
  let token;
  try {
    const timestamp = (await db.prepare("SELECT value FROM oauth WHERE key = ?").bind("timestamp").first())["value"];
    const parsedTimestamp = parseInt(timestamp);
    if (isNaN(parsedTimestamp) || Date.now() - parsedTimestamp >= 357e4) {
      try {
        const oauth = await getGoogleAuthToken(
          serviceAccount["client_email"],
          serviceAccount["private_key"],
          "https://www.googleapis.com/auth/firebase.messaging"
        );
        if (oauth.access_token) {
          const updateQuery = "UPDATE oauth SET value = ? WHERE key = ?";
          await db.prepare(updateQuery).bind(oauth.access_token, "token").run();
          await db.prepare(updateQuery).bind(Date.now().toString(), "timestamp").run();
          token = oauth.access_token;
        } else {
          throw new Error("Failed to obtain access token");
        }
      } catch (error) {
        throw new Error("Couldn't Generate token");
      }
    } else {
      token = (await db.prepare("SELECT value FROM oauth WHERE key = ?").bind("token").first())["value"];
      if (!token) {
        throw new Error("Token not found");
      }
    }
  } catch (error) {
    throw new Error("Error Handling Request " + error.message);
  }
  return token;
}

var D1_IMPORTS = ["__D1_BETA__DB"];

var D1Database = class {
  constructor(binding) {
    this.binding = binding;
  }
  prepare(query) {
    return new D1PreparedStatement(this, query);
  }
  async dump() {
    const response = await this.binding.fetch("http://d1/dump", {
      method: "POST",
      headers: {
        "content-type": "application/json"
      }
    });
    if (response.status !== 200) {
      try {
        const err = await response.json();
        throw new Error(`D1_DUMP_ERROR: ${err.error}`, {
          cause: new Error(err.error)
        });
      } catch (e) {
        throw new Error(`D1_DUMP_ERROR: Status + ${response.status}`, {
          cause: new Error("Status " + response.status)
        });
      }
    }
    return await response.arrayBuffer();
  }
  async batch(statements) {
    const exec = await this._send(
      "/query",
      statements.map((s) => s.statement),
      statements.map((s) => s.params)
    );
    return exec;
  }
  async exec(query) {
    const lines = query.trim().split("\n");
    const _exec = await this._send("/query", lines, [], false);
    const exec = Array.isArray(_exec) ? _exec : [_exec];
    const error = exec.map((r) => {
      return r.error ? 1 : 0;
    }).indexOf(1);
    if (error !== -1) {
      throw new Error(
        `D1_EXEC_ERROR: Error in line ${error + 1}: ${lines[error]}: ${exec[error].error}`,
        {
          cause: new Error(
            "Error in line " + (error + 1) + ": " + lines[error] + ": " + exec[error].error
          )
        }
      );
    } else {
      return {
        count: exec.length,
        duration: exec.reduce((p, c) => {
          return p + c.meta.duration;
        }, 0)
      };
    }
  }
  async _send(endpoint, query, params, dothrow = true) {
    const body = JSON.stringify(
      typeof query == "object" ? query.map((s, index) => {
        return { sql: s, params: params[index] };
      }) : {
        sql: query,
        params
      }
    );
    const response = await this.binding.fetch(new URL(endpoint, "http://d1"), {
      method: "POST",
      headers: {
        "content-type": "application/json"
      },
      body
    });
    try {
      const answer = await response.json();
      if (answer.error && dothrow) {
        const err = answer;
        throw new Error(`D1_ERROR: ${err.error}`, {
          cause: new Error(err.error)
        });
      } else {
        return Array.isArray(answer) ? answer.map((r) => mapD1Result(r)) : mapD1Result(answer);
      }
    } catch (e) {
      const error = e;
      throw new Error(`D1_ERROR: ${error.cause || "Something went wrong"}`, {
        cause: new Error(`${error.cause}` || "Something went wrong")
      });
    }
  }
};
var D1PreparedStatement = class {
  constructor(database, statement, params = []) {
    this.database = database;
    this.statement = statement;
    this.params = params;
  }
  bind(...values) {
    for (var r in values) {
      const value = values[r];
      switch (typeof value) {
        case "number":
        case "string":
          break;
        case "object":
          if (value == null)
            break;
          if (Array.isArray(value) && value.map((b) => {
            return typeof b == "number" && b >= 0 && b < 256 ? 1 : 0;
          }).indexOf(0) == -1)
            break;
          if (value instanceof ArrayBuffer) {
            values[r] = Array.from(new Uint8Array(value));
            break;
          }
          if (ArrayBuffer.isView(value)) {
            values[r] = Array.from(new Uint8Array(value.buffer));
            break;
          }
        default:
          throw new Error(
            `D1_TYPE_ERROR: Type '${typeof value}' not supported for value '${value}'`,
            {
              cause: new Error(
                `Type '${typeof value}' not supported for value '${value}'`
              )
            }
          );
      }
    }
    return new D1PreparedStatement(this.database, this.statement, values);
  }
  async first(colName) {
    const info = firstIfArray(
      await this.database._send("/query", this.statement, this.params)
    );
    const results = info.results;
    if (colName !== void 0) {
      if (results.length > 0 && results[0][colName] === void 0) {
        throw new Error(`D1_COLUMN_NOTFOUND: Column not found (${colName})`, {
          cause: new Error("Column not found")
        });
      }
      return results.length < 1 ? null : results[0][colName];
    } else {
      return results.length < 1 ? null : results[0];
    }
  }
  async run() {
    return firstIfArray(
      await this.database._send("/execute", this.statement, this.params)
    );
  }
  async all() {
    return firstIfArray(
      await this.database._send("/query", this.statement, this.params)
    );
  }
  async raw() {
    const s = firstIfArray(
      await this.database._send("/query", this.statement, this.params)
    );
    const raw = [];
    for (var r in s.results) {
      const entry = Object.keys(s.results[r]).map((k) => {
        return s.results[r][k];
      });
      raw.push(entry);
    }
    return raw;
  }
};
function firstIfArray(results) {
  return Array.isArray(results) ? results[0] : results;
}
function mapD1Result(result) {
  let map = {
    results: result.results || [],
    success: result.success === void 0 ? true : result.success,
    meta: result.meta || {}
  };
  result.error && (map.error = result.error);
  return map;
}
var D1_BETA_PREFIX = `__D1_BETA__`;
var envMap = /* @__PURE__ */ new Map();
function getMaskedEnv(env) {
  if (envMap.has(env))
    return envMap.get(env);
  const newEnv = new Map(Object.entries(env));
  D1_IMPORTS.filter(
    (bindingName) => bindingName.startsWith(D1_BETA_PREFIX)
  ).forEach((bindingName) => {
    newEnv.delete(bindingName);
    const newName = bindingName.slice(D1_BETA_PREFIX.length);
    const newBinding = new D1Database(env[bindingName]);
    newEnv.set(newName, newBinding);
  });
  const newEnvObj = Object.fromEntries(newEnv.entries());
  envMap.set(env, newEnvObj);
  return newEnvObj;
}
function wrap(env) {
  return getMaskedEnv(env);
}

var envWrappers = [wrap].filter(Boolean);
var facade = {
  ...src_default,
  envWrappers,
  middleware: [
    void 0,
    ...src_default.middleware ? src_default.middleware : []
  ].filter(Boolean)
};
var middleware_insertion_facade_default = facade;

var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
var __facade_modules_fetch__ = function(request, env, ctx) {
  if (middleware_insertion_facade_default.fetch === void 0)
    throw new Error("Handler does not export a fetch() function.");
  return middleware_insertion_facade_default.fetch(request, env, ctx);
};
function getMaskedEnv2(rawEnv) {
  let env = rawEnv;
  if (middleware_insertion_facade_default.envWrappers && middleware_insertion_facade_default.envWrappers.length > 0) {
    for (const wrapFn of middleware_insertion_facade_default.envWrappers) {
      env = wrapFn(env);
    }
  }
  return env;
}
var facade2 = {
  ...middleware_insertion_facade_default.tail && {
    tail: maskHandlerEnv(middleware_insertion_facade_default.tail)
  },
  ...middleware_insertion_facade_default.trace && {
    trace: maskHandlerEnv(middleware_insertion_facade_default.trace)
  },
  ...middleware_insertion_facade_default.scheduled && {
    scheduled: maskHandlerEnv(middleware_insertion_facade_default.scheduled)
  },
  ...middleware_insertion_facade_default.queue && {
    queue: maskHandlerEnv(middleware_insertion_facade_default.queue)
  },
  ...middleware_insertion_facade_default.test && {
    test: maskHandlerEnv(middleware_insertion_facade_default.test)
  },
  fetch(request, rawEnv, ctx) {
    const env = getMaskedEnv2(rawEnv);
    if (middleware_insertion_facade_default.middleware && middleware_insertion_facade_default.middleware.length > 0) {
      for (const middleware of middleware_insertion_facade_default.middleware) {
        __facade_register__(middleware);
      }
      const __facade_modules_dispatch__ = function(type, init) {
        if (type === "scheduled" && middleware_insertion_facade_default.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return middleware_insertion_facade_default.scheduled(controller, env, ctx);
        }
      };
      return __facade_invoke__(
        request,
        env,
        ctx,
        __facade_modules_dispatch__,
        __facade_modules_fetch__
      );
    } else {
      return __facade_modules_fetch__(request, env, ctx);
    }
  }
};
function maskHandlerEnv(handler) {
  return (data, env, ctx) => handler(data, getMaskedEnv2(env), ctx);
}
var middleware_loader_entry_default = facade2;
export {
  middleware_loader_entry_default as default
};
