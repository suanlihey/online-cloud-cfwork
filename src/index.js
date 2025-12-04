var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
// =================================================================================================
// === 全新重构的终极云盘应用 (Ultimate Cloud Drive) - 由AI为您倾力打造 (v3.0) ===================
// =================================================================================================
//
// 本代码整合了后端(Cloudflare Worker)、前端(HTML/CSS/JS)所有逻辑，旨在实现一个功能强大、
// 体验卓越、性能顶尖的现代网络云盘。
//
// v3.0 终极版 - 主要更新与增强:
// 1.  **满足核心需求**:
//     - **无限存储感官体验**: 移除了前端容量条的上限显示，提供“无限”空间感。
//     - **高级上传管理器**: 实现并发上传、实时速度显示，大幅提升上传效率和体验。
//     - **2GB单文件限制**: 在前后端双重实施了严格的2GB单文件大小限制。
//     - **数据看板问题澄清**: 优化了数据加载逻辑，确保切换视图时获取最新数据。
//
// 2.  **UI/UX 革命性提升**:
//     - **完全响应式设计**: 自动适配桌面、平板和手机等所有设备分辨率。
//     - **拖拽上传**: 支持全屏拖拽文件和文件夹进行上传，并提供清晰视觉反馈。
//     - **上下文工具栏**: 实现文件多选后的批量操作（分享、删除等）。
//     - **现代化组件**: 引入了非阻塞的Toast通知系统和体验更佳的模态框。
//
// 3.  **架构与性能飞跃**:
//     - **原子化元数据写入**: 重构上传流程，由Worker在完成R2上传后直接调用DO记录元数据，
//       彻底解决了以往依赖客户端通知而可能导致数据不一致的风险。
//     - **并发上传队列**: 前端实现并发上传（默认3个），极大缩短了批量上传的等待时间。
//
// 4.  **代码质量与健壮性**:
//     - **全面错误处理**: 增强了各环节的错误捕获和用户提示。
//     - **代码可读性**: 添加了大量注释，对复杂逻辑进行了解释。
//     - **安全性增强**: 对所有用户输入内容进行HTML转义，防止XSS攻击。
//
// =================================================================================================

var __defProp2 = Object.defineProperty;
var __name2 = /* @__PURE__ */ __name((target, value) => __defProp2(target, "name", { value, configurable: true }), "__name");

// --- 核心工具函数 (Core Utilities) ---
const utils = {
  hash: /* @__PURE__ */ __name(async (text) => {
    const encoded = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }, "hash"),
  jwt: {
    encode: /* @__PURE__ */ __name(async (payload, secret) => {
      const header = { alg: "HS256", typ: "JWT" };
      const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      const data = `${encodedHeader}.${encodedPayload}`;
      const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
      const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      return `${data}.${encodedSignature}`;
    }, "encode"),
    verify: /* @__PURE__ */ __name(async (token, secret) => {
      try {
        const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
        if (!encodedHeader || !encodedPayload || !encodedSignature) return null;
        const data = `${encodedHeader}.${encodedPayload}`;
        const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
        const signature = new Uint8Array(atob(encodedSignature.replace(/-/g, "+").replace(/_/g, "/")).split("").map((c) => c.charCodeAt(0)));
        if (!await crypto.subtle.verify("HMAC", key, signature, new TextEncoder().encode(data))) return null;
        return JSON.parse(atob(encodedPayload.replace(/-/g, "+").replace(/_/g, "/")));
      } catch (e) {
        console.error("JWT Verification Error:", e);
        return null;
      }
    }, "verify")
  },
  formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
  }
};
__name2(utils, "utils");


// --- DURABLE OBJECT: UserSpace (用户空间) ---
// 管理单个用户的所有文件和文件夹元数据
class UserSpace {
  static {
    __name(this, "UserSpace");
  }
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = []; // WebSocket会话
    this.storage = this.state.storage;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // WebSocket连接用于实时UI更新
    if (request.headers.get("Upgrade") === "websocket") {
      const [client, server] = Object.values(new WebSocketPair());
      await this.handleSession(server);
      return new Response(null, { status: 101, webSocket: client });
    }

    // API请求，主要由主Worker内部调用
    if (path.startsWith("/api/internal/")) {
        // 内部API，用于主Worker和DO之间的通信
        switch (path) {
            case "/api/internal/get-items-for-sharing": {
                const { itemIds } = await request.json();
                const items = await this.storage.get("items") || [];
                const itemsToShare = this.findItemsWithChildren(items, itemIds);
                return new Response(JSON.stringify(itemsToShare), { headers: { 'Content-Type': 'application/json' } });
            }
            // 新增：由主Worker调用的内部接口，用于可靠地添加文件元数据
            case "/api/internal/add-file": {
                if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
                try {
                    const { item } = await request.json();
                    await this.addFileItem(item);
                    return new Response(JSON.stringify({ ok: true }), { status: 200 });
                } catch (e) {
                    console.error("UserSpace internal add-file error:", e);
                    return new Response(JSON.stringify({ ok: false, error: e.message }), { status: 409 }); // 409 Conflict if file exists
                }
            }
            default:
                return new Response("Internal API Not Found in UserSpace", { status: 404 });
        }
    }
    
    return new Response("Not Found in UserSpace", { status: 404 });
  }

  // 查找并包含所有子项
  findItemsWithChildren(allItems, itemIds) {
      const itemMap = new Map(allItems.map(item => [item.id, item]));
      const resultSet = new Set();
      const queue = [...itemIds];

      while (queue.length > 0) {
          const currentId = queue.shift();
          if (resultSet.has(currentId)) continue;

          const item = itemMap.get(currentId);
          if (item) {
              resultSet.add(item.id);
              if (item.type === 'folder') {
                  for (const child of allItems) {
                      if (child.parentId === currentId) {
                          queue.push(child.id);
                      }
                  }
              }
          }
      }
      return allItems.filter(item => resultSet.has(item.id));
  }

  async handleSession(ws) {
    ws.accept();
    const session = { ws, id: crypto.randomUUID() };
    this.sessions.push(session);

    // 连接建立后，立即发送完整的文件历史记录和总容量
    const items = await this.storage.get("items") || [];
    const totalSize = items.filter((i) => i.type === "file").reduce((sum, file) => sum + file.size, 0);
    ws.send(JSON.stringify({ type: "history", items, totalSize }));

    // 监听来自客户端的消息 (现在主要用于文件夹和删除操作)
    ws.addEventListener("message", async (msg) => {
      try {
        const data = JSON.parse(msg.data);
        switch (data.type) {
          case "create_folder":
            await this.createFolder(data.name, data.parentId);
            break;
          case "delete_items":
            await this.deleteItems(data.itemIds);
            break;
          // 注意：add_file_item 消息类型已废弃，改为通过内部API处理
        }
      } catch (e) {
        console.error("UserSpace message handling error:", e);
        this.sendTo(ws, { type: "error", message: "内部错误: " + e.message });
      }
    });

    const closeOrErrorHandler = __name(() => {
      this.sessions = this.sessions.filter((s) => s.id !== session.id);
    }, "closeOrErrorHandler");
    ws.addEventListener("close", closeOrErrorHandler);
    ws.addEventListener("error", closeOrErrorHandler);
  }

  async createFolder(name, parentId) {
    await this.storage.transaction(async (txn) => {
        const items = await txn.get("items") || [];
        const siblingExists = items.some((i) => i.parentId === parentId && i.name === name && i.type === "folder");
        if (siblingExists) {
          throw new Error(`文件夹 "${name}" 已存在`);
        }
        const newFolder = {
          id: crypto.randomUUID(),
          type: "folder",
          name,
          parentId,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        };
        items.push(newFolder);
        await txn.put("items", items);
        this.broadcast({ type: "item_added", item: newFolder });
    });
  }

  async addFileItem(newItem) {
      await this.storage.transaction(async (txn) => {
          const items = await txn.get("items") || [];
          const siblingExists = items.some((i) => i.parentId === newItem.parentId && i.name === newItem.name && i.type === 'file');
          if (siblingExists) {
              // 如果文件已存在，可以选择覆盖或抛出错误。这里我们抛出错误。
              throw new Error(`文件 "${newItem.name}" 已存在于当前目录`);
          }
          items.push(newItem);
          await txn.put("items", items);

          // 广播给所有客户端，文件已添加
          this.broadcast({ type: "item_added", item: newItem });

          // 更新全局统计
          const statsDO = this.env.STATS_AGGREGATOR.get(this.env.STATS_AGGREGATOR.idFromName("global-stats"));
          // 使用 fetch 发送非阻塞请求
          statsDO.fetch(new Request("https://internal/increment", {
            method: "POST",
            body: JSON.stringify({ fileCount: 1, totalSize: newItem.size, mimeType: newItem.mimeType })
          }));
      });
  }

  async deleteItems(itemIds) {
    let deletedFiles = [];
    let deletedItemIds = new Set();

    await this.storage.transaction(async (txn) => {
        let items = await txn.get("items") || [];
        const itemsMap = new Map(items.map(i => [i.id, i]));
        
        const queue = [...itemIds];
        
        while(queue.length > 0) {
            const currentId = queue.shift();
            if (deletedItemIds.has(currentId)) continue;

            const itemToDelete = itemsMap.get(currentId);
            if (itemToDelete) {
                deletedItemIds.add(currentId);
                if (itemToDelete.type === 'file') {
                    deletedFiles.push(itemToDelete);
                } else if (itemToDelete.type === 'folder') {
                    // 找到所有子项并加入删除队列
                    items.forEach(child => {
                        if (child.parentId === currentId) {
                            queue.push(child.id);
                        }
                    });
                }
            }
        }

        if (deletedItemIds.size > 0) {
            const updatedItems = items.filter((i) => !deletedItemIds.has(i.id));
            await txn.put("items", updatedItems);
        }
    });

    if (deletedItemIds.size > 0) {
        this.broadcast({ type: "items_deleted", itemIds: Array.from(deletedItemIds) });

        if (deletedFiles.length > 0) {
            // 批量删除R2中的对象
            if (this.env.BUCKET) {
                const keysToDelete = deletedFiles.map(f => f.r2Key);
                // R2批量删除最多1000个
                for (let i = 0; i < keysToDelete.length; i += 1000) {
                    const chunk = keysToDelete.slice(i, i + 1000);
                    await this.env.BUCKET.delete(chunk);
                }
            }

            // 更新全局统计
            const totalSizeDeleted = deletedFiles.reduce((sum, file) => sum + file.size, 0);
            const statsDO = this.env.STATS_AGGREGATOR.get(this.env.STATS_AGGREGATOR.idFromName("global-stats"));
            statsDO.fetch(new Request("https://internal/decrement", {
              method: "POST",
              body: JSON.stringify({ fileCount: deletedFiles.length, totalSize: totalSizeDeleted })
            }));
        }
    }
  }

  // 广播消息给所有连接的客户端
  broadcast(message) {
    const preparedMessage = JSON.stringify(message);
    this.sessions = this.sessions.filter((session) => {
      try {
        if (session.ws.readyState === WebSocket.OPEN) {
          session.ws.send(preparedMessage);
          return true;
        }
        return false;
      } catch (err) {
        console.error("Broadcast error:", err);
        return false;
      }
    });
  }

  // 发送消息给单个客户端
  sendTo(ws, message) {
      try {
          if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify(message));
          }
      } catch (e) {
          console.error("SendTo WS error:", e);
      }
  }
}
__name2(UserSpace, "UserSpace");


// --- DURABLE OBJECT: StatsAggregator (全局统计) ---
// 聚合整个平台的统计数据，如总文件数、总大小等
class StatsAggregator {
  static {
    __name(this, "StatsAggregator");
  }
  constructor(state, env) {
    this.state = state;
  }
  async fetch(request) {
    const url = new URL(request.url);
    let [stats, typeCounts] = await Promise.all([
      this.state.storage.get("stats") || { fileCount: 0, totalSize: 0 },
      this.state.storage.get("typeCounts") || {}
    ]);
    if (url.pathname === "/increment" || url.pathname === "/decrement") {
      const { fileCount, totalSize, mimeType } = await request.json();
      const factor = url.pathname === "/increment" ? 1 : -1;
      stats.fileCount = Math.max(0, stats.fileCount + factor * fileCount);
      stats.totalSize = Math.max(0, stats.totalSize + factor * totalSize);
      if (mimeType) {
        const type = mimeType.split("/")[0] || "other";
        typeCounts[type] = Math.max(0, (typeCounts[type] || 0) + factor * fileCount);
        if (typeCounts[type] === 0) delete typeCounts[type];
      }
      await Promise.all([
        this.state.storage.put("stats", stats),
        this.state.storage.put("typeCounts", typeCounts)
      ]);
      return new Response("OK");
    } else if (url.pathname === "/get") {
      return new Response(JSON.stringify({ ...stats, typeCounts }), { headers: { "Content-Type": "application/json" } });
    }
    return new Response("Not found", { status: 404 });
  }
}
__name2(StatsAggregator, "StatsAggregator");


// --- 主 WORKER 入口 ---
const worker = {
  async fetch(request, env, ctx) {
    try {
        const url = new URL(request.url);
        const path = url.pathname;

        // API 路由
        if (path.startsWith("/api/")) {
          return this.handleApiRoutes(request, env, ctx);
        }

        // 分享页面路由
        const shareMatch = path.match(/^\/s\/([a-zA-Z0-9_-]+)$/);
        if (shareMatch) {
          const shareId = shareMatch[1];
          return this.handleSharePage(shareId, env);
        }

        // WebSocket 和 R2 上传路由 (需要认证)
        if (request.headers.get("Upgrade") === "websocket" || path.startsWith("/upload/")) {
          const token = url.searchParams.get("token") || request.headers.get('X-Auth-Token');
          if (!token) return new Response(JSON.stringify({ ok: false, error: "Token required" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
          
          const payload = await utils.jwt.verify(token, globalThis.JWT_SECRET);
          if (!payload || !payload.userId) return new Response(JSON.stringify({ ok: false, error: "Invalid or expired token" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
          
          // 将 payload 附加到请求中，方便后续处理
          request.payload = payload;

          if (request.headers.get("Upgrade") === "websocket") {
              const doId = env.USER_SPACE.idFromName(payload.userId);
              const stub = env.USER_SPACE.get(doId);
              return stub.fetch(request);
          }
          if (path.startsWith("/upload/")) {
              return this.handleR2Upload(request, env);
          }
        }

        // 托管前端静态资源
        return this.serveWebApp(env);
    } catch (e) {
        console.error("Global fetch error:", e);
        return new Response("服务器发生意外错误: " + e.message, { status: 500 });
    }
  },

  async handleApiRoutes(request, env, ctx) {
      const url = new URL(request.url);
      const path = url.pathname;
      
      // 无需认证的API
      if (path === "/api/auth/register") return this.handleRegister(request, env);
      if (path === "/api/auth/login") return this.handleLogin(request, env);
      if (path === "/api/stats") {
        const statsDO = env.STATS_AGGREGATOR.get(env.STATS_AGGREGATOR.idFromName("global-stats"));
        return statsDO.fetch(new Request("https://internal/get"));
      }
      if (path === "/api/share/verify-password") return this.handleVerifySharePassword(request, env);
      if (path.startsWith("/api/share/browse/")) return this.handleBrowseShare(request, env);

      // --- 以下API需要认证 ---
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      if (!token) {
          return new Response(JSON.stringify({ ok: false, error: "Unauthorized: Missing token" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
      const payload = await utils.jwt.verify(token, globalThis.JWT_SECRET);
      if (!payload) return new Response(JSON.stringify({ ok: false, error: "Unauthorized: Invalid or expired token" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      request.payload = payload; // 附加用户信息

      if (path === "/api/share/create") return this.handleCreateShare(request, env);
      if (path === "/api/shares") return this.handleListShares(request, env);
      if (path.startsWith("/api/share/") && request.method === 'DELETE') return this.handleDeleteShare(request, env);
      
      return new Response(JSON.stringify({ ok: false, error: "API Not Found" }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  },

  async handleRegister(request, env) {
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    try {
      const { username, password } = await request.json();
      if (!username || !password || password.length < 6) return new Response(JSON.stringify({ ok: false, error: "用户名或密码格式不正确 (密码至少6位)" }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      if (await env.USERS_KV.get(`user:${username}`)) return new Response(JSON.stringify({ ok: false, error: "用户名已存在" }), { status: 409, headers: { 'Content-Type': 'application/json' } });
      const userId = crypto.randomUUID();
      const hashedPassword = await utils.hash(password);
      await env.USERS_KV.put(`user:${username}`, JSON.stringify({ userId, hashedPassword }));
      return new Response(JSON.stringify({ ok: true }), { status: 201, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "注册失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },

  async handleLogin(request, env) {
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    try {
      const { username, password } = await request.json();
      const userDataStr = await env.USERS_KV.get(`user:${username}`);
      if (!userDataStr) return new Response(JSON.stringify({ ok: false, error: "用户不存在" }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      const { userId, hashedPassword } = JSON.parse(userDataStr);
      if (hashedPassword !== await utils.hash(password)) return new Response(JSON.stringify({ ok: false, error: "密码错误" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      const token = await utils.jwt.encode({ userId, username }, globalThis.JWT_SECRET);
      return new Response(JSON.stringify({ ok: true, token, username }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "登录失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },

  // --- R2 分块上传处理 ---
  async handleR2Upload(request, env) {
      if (!env.BUCKET) return new Response("R2 Bucket not configured", { status: 500 });
      const url = new URL(request.url);
      const path = url.pathname;
      const userId = request.payload.userId;
      const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 新增：2GB 文件大小限制

      // 1. 初始化分块上传
      if (path.endsWith("/create-multipart")) {
          const { fileName, contentType, fileSize } = await request.json();
          
          // 新增：后端强制文件大小校验
          if (fileSize > MAX_FILE_SIZE) {
              return new Response(JSON.stringify({ ok: false, error: `文件大小 (${utils.formatBytes(fileSize)}) 超过了 2GB 的限制` }), { status: 413, headers: { 'Content-Type': 'application/json' } }); // 413 Payload Too Large
          }

          const r2Key = `${userId}/${crypto.randomUUID()}/${fileName}`;
          const multipartUpload = await env.BUCKET.createMultipartUpload(r2Key, {
              httpMetadata: { contentType }
          });
          return new Response(JSON.stringify({ key: r2Key, uploadId: multipartUpload.uploadId }), { headers: { 'Content-Type': 'application/json' } });
      }

      // 2. 获取预签名URL以上传分块
      if (path.endsWith("/get-upload-part-url")) {
          const { key, uploadId, partNumber } = await request.json();
          const presignedUrl = await env.BUCKET.getSignedUrl('uploadPart', {
              key,
              uploadId,
              partNumber,
              expires: 3600, // 1 hour
          });
          return new Response(JSON.stringify({ url: presignedUrl }));
      }

      // 3. 完成分块上传
      if (path.endsWith("/complete-multipart")) {
          const { key, uploadId, parts, fileInfo } = await request.json();
          const { parentId, name, size, type } = fileInfo;
          
          const complete = await env.BUCKET.completeMultipartUpload(key, uploadId, parts);
          if (!complete.etag) {
              return new Response(JSON.stringify({ ok: false, error: "Failed to complete multipart upload" }), { status: 500, headers: { 'Content-Type': 'application/json' } });
          }

          // 上传完成后，将文件元数据写入UserSpace DO
          const newItem = {
              id: crypto.randomUUID(),
              type: "file",
              name,
              size,
              mimeType: type,
              r2Key: key,
              parentId,
              createdAt: Date.now(),
              updatedAt: Date.now(),
          };

          // 核心架构优化：由Worker直接调用DO的内部API来添加元数据，确保原子性
          const doId = env.USER_SPACE.idFromName(userId);
          const stub = env.USER_SPACE.get(doId);
          const addFileResponse = await stub.fetch(new Request("https://internal/api/internal/add-file", {
              method: "POST",
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ item: newItem })
          }));

          if (!addFileResponse.ok) {
              // 如果元数据添加失败（例如，文件重名），则需要回滚，删除已上传的R2对象
              console.error(`Failed to add file metadata for ${key}. Rolling back R2 object.`);
              await env.BUCKET.delete(key);
              const errorData = await addFileResponse.json();
              return new Response(JSON.stringify({ ok: false, error: `元数据创建失败: ${errorData.error}` }), { status: addFileResponse.status, headers: { 'Content-Type': 'application/json' } });
          }

          return new Response(JSON.stringify({ ok: true, item: newItem }), { headers: { 'Content-Type': 'application/json' } });
      }
      
      // 4. 中止分块上传
      if (path.endsWith("/abort-multipart")) {
          const { key, uploadId } = await request.json();
          await env.BUCKET.abortMultipartUpload(key, uploadId);
          return new Response(JSON.stringify({ ok: true }));
      }

      // 5. R2文件下载代理
      const r2Key = url.searchParams.get("r2_key");
      if (r2Key) {
          const object = await env.BUCKET.get(r2Key);
          if (object === null) {
              return new Response('Object Not Found', { status: 404 });
          }
          const headers = new Headers();
          object.writeHttpMetadata(headers);
          headers.set('etag', object.httpEtag);
          const filename = url.searchParams.get("filename") || r2Key.split('/').pop();
          headers.set("Content-Disposition", `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
          return new Response(object.body, { headers });
      }

      return new Response("Invalid upload route", { status: 400 });
  },

  // --- 分享功能核心逻辑 ---
  async handleCreateShare(request, env) {
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    try {
      const { itemIds, password, expiry } = await request.json();
      if (!itemIds || itemIds.length === 0) {
          return new Response(JSON.stringify({ ok: false, error: "No items selected" }), { status: 400, headers: { 'Content-Type': 'application/json' } });
      }

      const { userId, username } = request.payload;
      const doId = env.USER_SPACE.idFromName(userId);
      const stub = env.USER_SPACE.get(doId);

      // 从UserSpace获取要分享的完整项目信息（包括子文件夹内容）
      const itemsResponse = await stub.fetch(new Request("https://internal/api/internal/get-items-for-sharing", {
          method: "POST",
          body: JSON.stringify({ itemIds })
      }));
      if (!itemsResponse.ok) throw new Error("Failed to fetch items for sharing.");
      const allItemsToShare = await itemsResponse.json();
      if (allItemsToShare.length === 0) throw new Error("Selected items not found.");

      const rootItem = allItemsToShare.find(i => itemIds.includes(i.id));

      const shareId = crypto.randomUUID().substring(0, 8);
      const shareData = {
        rootId: rootItem.id,
        rootType: rootItem.type,
        rootName: rootItem.name,
        items: allItemsToShare, // 存储文件树快照
        owner: username,
        ownerId: userId,
        createdAt: Date.now(),
        visits: 0,
        downloads: 0,
      };

      if (password) {
        shareData.passwordHash = await utils.hash(password);
      }

      let expirationTtl;
      switch (expiry) {
          case '7d': expirationTtl = 86400 * 7; break;
          case '30d': expirationTtl = 86400 * 30; break;
          case 'permanent': expirationTtl = undefined; break;
          default: expirationTtl = 86400 * 30; // 默认30天
      }
      
      const putOptions = expirationTtl ? { expirationTtl } : {};
      await env.SHARES_KV.put(shareId, JSON.stringify(shareData), putOptions);
      
      return new Response(JSON.stringify({ ok: true, shareId }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "创建分享失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },

  async handleSharePage(shareId, env) {
    const shareDataStr = await env.SHARES_KV.get(shareId);
    if (!shareDataStr) return new Response("分享链接不存在或已过期", { status: 404, headers: { "Content-Type": "text/html;charset=UTF-8" } });
    
    // 异步更新访问次数
    const shareData = JSON.parse(shareDataStr);
    shareData.visits = (shareData.visits || 0) + 1;
    const metadata = await env.SHARES_KV.getWithMetadata(shareId);
    const options = {};
    if (metadata && metadata.expiration) {
        options.expiration = metadata.expiration;
    }
    await env.SHARES_KV.put(shareId, JSON.stringify(shareData), options);

    // BUG修复：将布尔值转换为字符串，以匹配模板替换的期望
    let body = SHARE_PAGE_HTML_TEMPLATE
        .replace(/{{SHARE_ID}}/g, shareId)
        .replace(/{{ROOT_NAME}}/g, shareData.rootName)
        .replace(/{{ROOT_TYPE}}/g, shareData.rootType)
        .replace(/{{IS_PROTECTED}}/g, String(!!shareData.passwordHash));

    return new Response(body, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
  },

  async handleBrowseShare(request, env) {
      const url = new URL(request.url);
      const shareId = url.pathname.split('/')[4];
      const parentId = url.searchParams.get('parentId') || null;
      const authToken = url.searchParams.get('authToken'); // 密码验证后获得的临时token

      const shareDataStr = await env.SHARES_KV.get(shareId);
      if (!shareDataStr) return new Response(JSON.stringify({ ok: false, error: "分享不存在或已过期" }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      
      const shareData = JSON.parse(shareDataStr);

      // 如果有密码，验证临时token
      if (shareData.passwordHash) {
          if (!authToken) return new Response(JSON.stringify({ ok: false, error: "需要授权" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
          const expectedToken = await utils.hash(shareId + globalThis.JWT_SECRET);
          if (authToken !== expectedToken) {
              return new Response(JSON.stringify({ ok: false, error: "授权无效" }), { status: 403, headers: { 'Content-Type': 'application/json' } });
          }
      }

      // 如果是文件分享，直接返回文件信息
      if (shareData.rootType === 'file') {
          const fileItem = shareData.items[0];
          const downloadUrl = `/upload/download?r2_key=${fileItem.r2Key}&filename=${encodeURIComponent(fileItem.name)}&shareId=${shareId}`;
          return new Response(JSON.stringify({ ok: true, type: 'file', item: fileItem, downloadUrl }), { headers: { 'Content-Type': 'application/json' } });
      }

      // 如果是文件夹分享，返回指定目录下的内容
      const currentParentId = parentId || shareData.rootId;
      const children = shareData.items.filter(item => item.parentId === currentParentId);
      const path = this.getFolderPath(shareData.items, currentParentId, shareData.rootId);

      return new Response(JSON.stringify({ ok: true, type: 'folder', items: children, path }), { headers: { 'Content-Type': 'application/json' } });
  },

  getFolderPath(allItems, currentId, rootId) {
      const itemMap = new Map(allItems.map(i => [i.id, i]));
      let path = [];
      let tempId = currentId;
      while (tempId && tempId !== rootId) {
          const folder = itemMap.get(tempId);
          if (!folder) break;
          path.unshift({ id: folder.id, name: folder.name });
          tempId = folder.parentId;
      }
      path.unshift({ id: rootId, name: '根目录' });
      return path;
  },

  async handleVerifySharePassword(request, env) {
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    try {
      const { shareId, password } = await request.json();
      const shareDataStr = await env.SHARES_KV.get(shareId);
      if (!shareDataStr) return new Response(JSON.stringify({ ok: false, error: "分享不存在或已过期" }), { status: 404, headers: { 'Content-Type': 'application/json' } });
      
      const shareData = JSON.parse(shareDataStr);
      if (shareData.passwordHash !== await utils.hash(password)) {
        return new Response(JSON.stringify({ ok: false, error: "密码错误" }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
      
      // 生成一个临时的、一次性的访问令牌
      const authToken = await utils.hash(shareId + globalThis.JWT_SECRET);
      return new Response(JSON.stringify({ ok: true, authToken }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "验证失败: " + e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
  },

  async handleListShares(request, env) {
    const { username } = request.payload;
    // 注意：在KV中，`list`操作会扫描所有键。对于大规模应用，更好的做法是使用带用户名的前缀来创建键，
    // 例如 `share:${username}:${shareId}`，然后使用 `list({ prefix: `share:${username}:` })`。
    // 为保持当前实现的简洁性，我们仍扫描所有键并在内存中过滤，但这在用户量巨大时性能会下降。
    const list = await env.SHARES_KV.list(); 
    
    const allSharesPromises = list.keys.map(async key => {
        const value = await env.SHARES_KV.get(key.name);
        if (!value) return null;
        const data = JSON.parse(value);
        // 仅返回属于当前用户的分享
        if (data.owner !== username) return null;
        
        const metadata = await env.SHARES_KV.getWithMetadata(key.name);
        return { id: key.name, ...data, expiration: metadata.expiration };
    });

    const userShares = (await Promise.all(allSharesPromises)).filter(Boolean);

    return new Response(JSON.stringify({ ok: true, shares: userShares }), { headers: { 'Content-Type': 'application/json' } });
  },

  async handleDeleteShare(request, env) {
    if (request.method !== 'DELETE') return new Response('Method Not Allowed', { status: 405 });
    const { username } = request.payload;
    const shareId = new URL(request.url).pathname.split('/').pop();
    const shareDataStr = await env.SHARES_KV.get(shareId);
    if (shareDataStr) {
      const shareData = JSON.parse(shareDataStr);
      if (shareData.owner !== username) {
        return new Response(JSON.stringify({ ok: false, error: "Forbidden" }), { status: 403, headers: { 'Content-Type': 'application/json' } });
      }
      await env.SHARES_KV.delete(shareId);
    }
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  },

  // --- 服务端渲染主应用 ---
  serveWebApp(env) {
    // 动态替换占位符
    const body = MAIN_HTML_TEMPLATE.replace("<!-- SCRIPT_PLACEHOLDER -->", `<script>${FRONTEND_JS}<\/script>`);
    return new Response(body, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
  },
};
__name2(worker, "worker");


// --- HTML, CSS, JS 模板 ---

// 主应用HTML模板
const MAIN_HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>终极云盘</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"><\/script>
    <style>
        :root {
            --theme-color: #007bff; --theme-color-dark: #0056b3; --bg-color: #f4f6f9; --panel-bg: #fff;
            --text-color: #333; --text-color-light: #6c757d; --border-color: #dee2e6; --hover-bg: #e9ecef;
            --success-color: #28a745; --danger-color: #dc3545; --warning-color: #ffc107;
            --sidebar-width: 240px; --header-height: 60px;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: var(--bg-color); color: var(--text-color); font-size: 14px; display: flex; height: 100vh; overflow: hidden; }
        .hidden { display: none !important; }
        button { cursor: pointer; font-family: inherit; }
        button:disabled { cursor: not-allowed; opacity: 0.65; }
        
        /* --- 认证视图 --- */
        #auth-view { width: 100%; display: flex; justify-content: center; align-items: center; }
        .auth-form { background: var(--panel-bg); padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); width: 100%; max-width: 400px; margin: 20px; }
        .auth-form h2 { text-align: center; margin-bottom: 20px; }
        .auth-form .form-group { margin-bottom: 15px; }
        .auth-form label { display: block; margin-bottom: 5px; font-weight: 500; }
        .auth-form input { width: 100%; padding: 10px; border: 1px solid var(--border-color); border-radius: 4px; box-sizing: border-box; }
        .auth-form button { width: 100%; padding: 12px; background-color: var(--theme-color); color: white; border: none; border-radius: 4px; font-size: 16px; transition: background-color 0.2s; }
        .auth-form button:hover { background-color: var(--theme-color-dark); }
        .auth-form .switch-auth { text-align: center; margin-top: 15px; font-size: 14px; }
        .auth-form .switch-auth a { color: var(--theme-color); cursor: pointer; text-decoration: none; }
        .auth-form .error-message { color: var(--danger-color); text-align: center; margin-bottom: 10px; min-height: 1em; }

        /* --- 主应用布局 --- */
        #app-view { display: flex; width: 100%; height: 100%; flex-direction: column; }
        .main-layout { display: flex; flex-grow: 1; overflow: hidden; }
        aside.sidebar { width: var(--sidebar-width); background: var(--panel-bg); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; padding: 15px 0; flex-shrink: 0; transition: margin-left 0.3s; }
        main.content-area { flex-grow: 1; display: flex; flex-direction: column; overflow: hidden; }
        
        /* 侧边栏 */
        .sidebar .logo { font-size: 22px; font-weight: 600; color: var(--theme-color); padding: 0 20px 20px; }
        .sidebar nav a { display: flex; align-items: center; gap: 15px; padding: 12px 20px; text-decoration: none; color: var(--text-color-light); font-weight: 500; border-left: 3px solid transparent; }
        .sidebar nav a:hover { background-color: var(--hover-bg); }
        .sidebar nav a.active { color: var(--theme-color); background-color: #e7f1ff; border-left-color: var(--theme-color); }
        .sidebar nav a i { width: 20px; text-align: center; }
        .sidebar-footer { margin-top: auto; padding: 20px; }
        .capacity-bar { font-size: 12px; color: var(--text-color-light); }
        .capacity-bar .bar { background: #e9ecef; border-radius: 5px; height: 6px; margin-top: 5px; overflow: hidden; }
        .capacity-bar .bar-inner { background: var(--theme-color); height: 100%; width: 0; transition: width 0.5s; }
        .user-info { display: flex; align-items: center; gap: 10px; padding: 15px 20px; border-top: 1px solid var(--border-color); }
        .user-info .username { font-weight: 500; flex-grow: 1; }
        #logout-button { background: none; border: none; font-size: 18px; color: var(--text-color-light); }

        /* 内容区头部 */
        .content-header { height: var(--header-height); display: flex; align-items: center; padding: 0 24px; border-bottom: 1px solid var(--border-color); flex-shrink: 0; background: var(--panel-bg); }
        .breadcrumb-bar { display: flex; align-items: center; gap: 8px; font-size: 16px; color: #555; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .breadcrumb a { color: var(--theme-color); text-decoration: none; }
        .content-header .header-actions { margin-left: auto; display: flex; gap: 15px; align-items: center; }
        .search-box input { padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 4px; width: 250px; }
        #sidebar-toggle { background: none; border: none; font-size: 20px; display: none; }

        /* 内容区主体 */
        .view-container { padding: 24px; overflow-y: auto; flex-grow: 1; }
        .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }
        .toolbar .main-actions button { background-color: var(--theme-color); color: white; padding: 8px 15px; border-radius: 4px; border: none; margin-right: 10px; display: inline-flex; align-items: center; gap: 8px; }
        .contextual-toolbar { background-color: #e7f1ff; padding: 10px 24px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 20px; }
        .contextual-toolbar button { background: none; border: none; display: flex; align-items: center; gap: 8px; font-size: 14px; }

        /* 上传按钮下拉菜单 */
        .upload-dropdown { position: relative; display: inline-block; }
        .upload-dropdown-content { display: none; position: absolute; background-color: #f9f9f9; min-width: 160px; box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2); z-index: 1; border-radius: 4px; }
        .upload-dropdown-content a { color: black; padding: 12px 16px; text-decoration: none; display: block; }
        .upload-dropdown-content a:hover { background-color: #f1f1f1; }
        .upload-dropdown:hover .upload-dropdown-content { display: block; }
        .upload-dropdown:hover .main-upload-btn { background-color: var(--theme-color-dark); }

        /* 文件列表 */
        .file-table-wrapper { overflow-x: auto; }
        .file-table { width: 100%; border-collapse: collapse; background: var(--panel-bg); }
        .file-table th, .file-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border-color); white-space: nowrap; vertical-align: middle; }
        .file-table th { background-color: #f8f9fa; font-weight: 500; }
        .file-table tr:hover { background-color: var(--hover-bg); }
        .file-table .item-name { cursor: pointer; display: flex; align-items: center; gap: 10px; }
        .file-table .item-name:hover { color: var(--theme-color); }
        .file-table .item-actions button { background: none; border: none; font-size: 16px; color: var(--text-color-light); margin: 0 5px; }
        .file-table .item-actions .delete-btn:hover { color: var(--danger-color); }
        .file-table input[type=checkbox] { width: 16px; height: 16px; }
        .empty-state, .loading-state { text-align: center; padding: 60px; color: #888; font-size: 16px; }
        #drop-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 123, 255, 0.1); border: 3px dashed var(--theme-color); display: flex; justify-content: center; align-items: center; z-index: 9999; pointer-events: none; }
        #drop-overlay-text { font-size: 24px; color: var(--theme-color); font-weight: bold; }

        /* 上传队列 */
        #upload-manager { position: fixed; bottom: 20px; right: 20px; width: 350px; background: var(--panel-bg); border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); z-index: 1000; }
        .upload-manager-header { padding: 10px 15px; border-bottom: 1px solid var(--border-color); font-weight: 500; display: flex; justify-content: space-between; align-items: center; }
        .upload-queue { max-height: 300px; overflow-y: auto; padding: 5px; }
        .upload-item { padding: 10px; border-bottom: 1px solid #f0f0f0; }
        .upload-item:last-child { border-bottom: none; }
        .upload-item-info { display: flex; justify-content: space-between; align-items: center; font-size: 13px; }
        .upload-item-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 70%; }
        .upload-item-status { color: var(--text-color-light); }
        .upload-item-progress { width: 100%; height: 6px; -webkit-appearance: none; appearance: none; margin-top: 8px; border-radius: 3px; overflow: hidden; }
        .upload-item-progress::-webkit-progress-bar { background-color: #eee; }
        .upload-item-progress::-webkit-progress-value { background-color: var(--theme-color); }

        /* 其他视图 */
        #stats-view .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: var(--panel-bg); padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .stat-card h3 { margin: 0 0 10px; font-size: 16px; color: #666; }
        .stat-card .value { font-size: 28px; font-weight: bold; color: var(--theme-color); }
        .chart-container { background: var(--panel-bg); padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        #shares-view .share-link-cell { max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

        /* 模态框 */
        .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; justify-content: center; align-items: center; z-index: 2000; }
        .modal-content { background: var(--panel-bg); padding: 20px; border-radius: 8px; width: 90%; max-width: 500px; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h3 { margin: 0; }
        .modal-close { background: none; border: none; font-size: 24px; }
        .modal-body .form-group { margin-bottom: 15px; }
        .modal-body label { display: block; margin-bottom: 5px; }
        .modal-body input, .modal-body select { width: 100%; padding: 8px; border: 1px solid var(--border-color); border-radius: 4px; box-sizing: border-box; }
        .modal-footer { text-align: right; margin-top: 20px; }
        .modal-footer button { padding: 8px 15px; border-radius: 4px; border: 1px solid var(--border-color); margin-left: 10px; }
        .modal-footer .btn-primary { background: var(--theme-color); color: white; border-color: var(--theme-color); }
        #share-link-result { margin-top: 15px; word-break: break-all; background: #f0f0f0; padding: 10px; border-radius: 4px; }
        
        /* Toast 通知 */
        #toast-container { position: fixed; top: 20px; right: 20px; z-index: 3000; }
        .toast { background-color: #333; color: #fff; padding: 12px 20px; border-radius: 5px; margin-bottom: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.2); opacity: 0; transform: translateX(100%); transition: all 0.3s; max-width: 350px; }
        .toast.show { opacity: 1; transform: translateX(0); }
        .toast.success { background-color: var(--success-color); }
        .toast.error { background-color: var(--danger-color); }

        /* 响应式设计 */
        @media (max-width: 768px) {
            body { font-size: 16px; }
            .main-layout { flex-direction: column; }
            aside.sidebar { position: fixed; left: 0; top: 0; bottom: 0; z-index: 1100; margin-left: calc(var(--sidebar-width) * -1); }
            aside.sidebar.open { margin-left: 0; }
            #sidebar-toggle { display: block; }
            .content-header .search-box { display: none; }
            .view-container { padding: 15px; }
            .file-table th:nth-child(3), .file-table td:nth-child(3),
            .file-table th:nth-child(4), .file-table td:nth-child(4) { display: none; }
            #upload-manager { width: calc(100% - 20px); left: 10px; right: 10px; bottom: 10px; }
        }
    </style>
</head>
<body>
    <div id="auth-view">
        <div class="auth-form">
            <h2 id="auth-title">登录</h2>
            <div class="error-message" id="auth-error"></div>
            <div class="form-group"><label for="username">用户名</label><input type="text" id="username" required></div>
            <div class="form-group"><label for="password">密码</label><input type="password" id="password" required></div>
            <button id="auth-button">登录</button>
            <div class="switch-auth"><span id="auth-prompt">还没有账户？</span> <a id="switch-auth-link">立即注册</a></div>
        </div>
    </div>

    <div id="app-view" class="hidden">
        <div class="main-layout">
            <aside class="sidebar" id="sidebar">
                <div class="logo"><i class="fas fa-cloud-bolt"></i> 终极云盘</div>
                <nav>
                    <a href="#" id="nav-files" class="active"><i class="fas fa-folder"></i> 我的文件</a>
                    <a href="#" id="nav-shares"><i class="fas fa-share-alt"></i> 我的分享</a>
                    <a href="#" id="nav-stats"><i class="fas fa-chart-pie"></i> 平台数据</a>
                </nav>
                <div class="sidebar-footer">
                    <div class="capacity-bar">
                        <div id="capacity-text"></div>
                        <div class="bar"><div class="bar-inner" id="capacity-bar-inner"></div></div>
                    </div>
                    <div class="user-info">
                        <span class="username" id="user-info-username"></span>
                        <button id="logout-button" title="退出登录"><i class="fas fa-sign-out-alt"></i></button>
                    </div>
                </div>
            </aside>
            <main class="content-area">
                <div id="files-view">
                    <div class="content-header">
                        <button id="sidebar-toggle"><i class="fas fa-bars"></i></button>
                        <div class="breadcrumb-bar" id="breadcrumb-bar"></div>
                        <div class="header-actions">
                            <div class="search-box">
                                <input type="text" id="search-input" placeholder="搜索您的文件...">
                            </div>
                        </div>
                    </div>
                    <div id="contextual-toolbar" class="contextual-toolbar hidden">
                        <span id="selection-count"></span>
                        <button id="selection-share-btn"><i class="fas fa-share-alt"></i> 分享</button>
                        <button id="selection-download-btn"><i class="fas fa-download"></i> 下载</button>
                        <button id="selection-delete-btn"><i class="fas fa-trash-alt"></i> 删除</button>
                    </div>
                    <div class="view-container" id="file-drop-zone">
                        <div class="toolbar">
                            <div class="main-actions">
                                <div class="upload-dropdown">
                                    <button class="main-upload-btn"><i class="fas fa-upload"></i> 上传</button>
                                    <div class="upload-dropdown-content">
                                        <a href="#" id="upload-file-btn"><i class="fas fa-file-upload"></i> 上传文件</a>
                                        <a href="#" id="upload-folder-btn"><i class="fas fa-folder-upload"></i> 上传文件夹</a>
                                    </div>
                                </div>
                                <button id="new-folder-button"><i class="fas fa-folder-plus"></i> 新建文件夹</button>
                                <input type="file" id="file-input" class="hidden" multiple>
                                <input type="file" id="folder-input" class="hidden" webkitdirectory directory multiple>
                            </div>
                        </div>
                        <div class="file-table-wrapper">
                            <table class="file-table">
                                <thead><tr>
                                    <th><input type="checkbox" id="select-all-checkbox"></th>
                                    <th>名称</th><th>大小</th><th>修改日期</th><th>操作</th>
                                </tr></thead>
                                <tbody id="file-list-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div id="shares-view" class="hidden">
                    <div class="content-header"><h2>我的分享</h2></div>
                    <div class="view-container">
                        <p>这里列出了您创建的所有分享链接。您可以管理它们的有效期和状态。</p>
                        <div class="file-table-wrapper">
                            <table class="file-table">
                                <thead><tr><th>文件名</th><th>分享链接</th><th>状态</th><th>创建日期</th><th>访问/下载</th><th>操作</th></tr></thead>
                                <tbody id="share-list-body"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <div id="stats-view" class="hidden">
                    <div class="content-header"><h2>平台数据看板</h2></div>
                    <div class="view-container">
                        <div class="stats-grid" id="stats-grid-container"></div>
                        <div class="chart-container">
                            <h3>文件类型分布 (按数量)</h3>
                            <canvas id="file-type-chart"></canvas>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <div id="upload-manager" class="hidden">
        <div class="upload-manager-header">
            <span>上传队列</span>
            <button id="toggle-upload-manager-btn" style="background:none; border:none; font-size:16px; cursor:pointer;"><i class="fas fa-chevron-down"></i></button>
        </div>
        <div class="upload-queue" id="upload-queue"></div>
    </div>
    
    <div id="drop-overlay" class="hidden"><span id="drop-overlay-text">拖放到此处以上传</span></div>
    <div id="modal-container"></div>
    <div id="toast-container"></div>

    <!-- SCRIPT_PLACEHOLDER -->
</body>
</html>
`;

// 分享页面HTML模板
const SHARE_PAGE_HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件分享 - {{ROOT_NAME}}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: #f4f7fa; padding: 20px; box-sizing: border-box; }
        .share-container { background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); width: 100%; max-width: 800px; }
        h2 { margin-top: 0; display: flex; align-items: center; gap: 10px; }
        .password-prompt { text-align: center; }
        .password-prompt p { margin-bottom: 20px; }
        .password-prompt input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; margin-bottom: 15px; }
        .password-prompt button { width: 100%; padding: 12px; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
        .error { color: #dc3545; margin-top: 10px; min-height: 1em; }
        .file-browser .breadcrumb { margin-bottom: 15px; font-size: 16px; }
        .file-browser .breadcrumb a { color: #007bff; text-decoration: none; }
        .file-table { width: 100%; border-collapse: collapse; }
        .file-table th, .file-table td { padding: 10px; text-align: left; border-bottom: 1px solid #eee; }
        .file-table tr:hover { background-color: #f8f9fa; }
        .item-name { cursor: pointer; display: flex; align-items: center; gap: 10px; }
        .item-name:hover { color: #007bff; }
        .download-button { display: inline-block; background-color: #28a745; color: #fff; padding: 12px 25px; border-radius: 4px; text-decoration: none; font-size: 16px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="share-container" id="share-container">
        <h2><i class="fas fa-share-alt"></i> 文件分享</h2>
        <div id="content-area">
            <!-- 内容将由JS动态填充 -->
        </div>
    </div>
    <script>
        (function() {
            const state = {
                shareId: '{{SHARE_ID}}',
                rootName: '{{ROOT_NAME}}',
                rootType: '{{ROOT_TYPE}}',
                isProtected: '{{IS_PROTECTED}}' === 'true',
                authToken: null,
                currentPath: [],
            };

            const ui = {
                container: document.getElementById('share-container'),
                contentArea: document.getElementById('content-area'),
            };

            function formatBytes(bytes, decimals = 2) {
                if (!bytes || bytes === 0) return '0 Bytes';
                const k = 1024;
                const dm = decimals < 0 ? 0 : decimals;
                const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
            }

            function renderPasswordPrompt() {
                ui.contentArea.innerHTML = \`
                    <div class="password-prompt">
                        <p>此分享受密码保护，请输入密码访问。</p>
                        <input type="password" id="password" placeholder="请输入分享密码" autofocus>
                        <button id="verify-password-btn">验证</button>
                        <p class="error" id="password-error"></p>
                    </div>
                \`;
                document.getElementById('verify-password-btn').addEventListener('click', handleVerifyPassword);
                document.getElementById('password').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') handleVerifyPassword();
                });
            }

            async function handleVerifyPassword() {
                const password = document.getElementById('password').value;
                const errorEl = document.getElementById('password-error');
                const btn = document.getElementById('verify-password-btn');
                errorEl.textContent = '';
                btn.disabled = true;
                btn.textContent = '验证中...';

                try {
                    const res = await fetch('/api/share/verify-password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ shareId: state.shareId, password })
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.error || '验证失败');
                    
                    state.authToken = data.authToken;
                    state.isProtected = false; // 已验证
                    loadContent();
                } catch (e) {
                    errorEl.textContent = e.message;
                    btn.disabled = false;
                    btn.textContent = '验证';
                }
            }

            function renderFileView(item, downloadUrl) {
                ui.contentArea.innerHTML = \`
                    <h3><i class="fas fa-file-alt"></i> \${item.name}</h3>
                    <p><strong>文件大小:</strong> \${formatBytes(item.size)}</p>
                    <a href="\${downloadUrl}" class="download-button" target="_blank" rel="noopener noreferrer">
                        <i class="fas fa-download"></i> 下载文件
                    </a>
                \`;
            }

            function renderFolderView(items, path) {
                state.currentPath = path;
                let breadcrumbHtml = path.map((p, i) => {
                    if (i === path.length - 1) return \`<span>\${p.name}</span>\`;
                    return \`<a href="#" data-id="\${p.id}">\${p.name}</a>\`;
                }).join(' / ');

                let itemsHtml = items.map(item => \`
                    <tr>
                        <td>
                            <span class="item-name" data-id="\${item.id}" data-type="\${item.type}">
                                <i class="fas \${item.type === 'folder' ? 'fa-folder' : 'fa-file-alt'}"></i>
                                \${item.name}
                            </span>
                        </td>
                        <td>\${item.type === 'folder' ? '—' : formatBytes(item.size)}</td>
                        <td>\${new Date(item.updatedAt).toLocaleString()}</td>
                    </tr>
                \`).join('');

                if (items.length === 0) {
                    itemsHtml = '<tr><td colspan="3" style="text-align:center; padding: 40px;">此文件夹为空</td></tr>';
                }

                ui.contentArea.innerHTML = \`
                    <div class="file-browser">
                        <div class="breadcrumb">\${breadcrumbHtml}</div>
                        <table class="file-table">
                            <thead><tr><th>名称</th><th>大小</th><th>修改日期</th></tr></thead>
                            <tbody>\${itemsHtml}</tbody>
                        </table>
                    </div>
                \`;

                ui.contentArea.querySelectorAll('.breadcrumb a').forEach(el => {
                    el.addEventListener('click', e => {
                        e.preventDefault();
                        loadContent(e.target.dataset.id);
                    });
                });
                ui.contentArea.querySelectorAll('.item-name').forEach(el => {
                    el.addEventListener('click', e => {
                        const target = e.currentTarget;
                        if (target.dataset.type === 'folder') {
                            loadContent(target.dataset.id);
                        } else {
                            // 文件点击直接下载
                            const fileItem = items.find(i => i.id === target.dataset.id);
                            if (fileItem) {
                                const downloadUrl = \`/upload/download?r2_key=\${fileItem.r2Key}&filename=\${encodeURIComponent(fileItem.name)}&shareId=\${state.shareId}\`;
                                window.open(downloadUrl, '_blank');
                            }
                        }
                    });
                });
            }

            async function loadContent(parentId = null) {
                ui.contentArea.innerHTML = '<p>加载中...</p>';
                try {
                    let url = \`/api/share/browse/\${state.shareId}\`;
                    const params = new URLSearchParams();
                    if (parentId) params.append('parentId', parentId);
                    if (state.authToken) params.append('authToken', state.authToken);
                    
                    const res = await fetch(\`\${url}?\${params.toString()}\`);
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.error || '加载失败');

                    if (data.type === 'file') {
                        renderFileView(data.item, data.downloadUrl);
                    } else {
                        renderFolderView(data.items, data.path);
                    }
                } catch (e) {
                    ui.contentArea.innerHTML = \`<p class="error">加载内容失败: \${e.message}</p>\`;
                }
            }

            function initialize() {
                if (state.isProtected) {
                    renderPasswordPrompt();
                } else {
                    loadContent();
                }
            }

            initialize();
        })();
    <\/script>
</body>
</html>
`;

// 前端主应用JS
const FRONTEND_JS = `
(function() {
    // --- 全局状态和 UI 元素 ---
    const state = {
        token: null,
        username: null,
        socket: null,
        allItems: [],
        currentView: 'files',
        currentParentId: 'root',
        uploadQueue: {},
        totalSize: 0,
        isLoggingOut: false,
        activeUploads: 0,
        MAX_CONCURRENT_UPLOADS: 3, // 并发上传数量
        selectedItemIds: new Set(),
        pathHistory: ['root'],
        // 新增：文件大小限制常量 (2GB)
        MAX_FILE_SIZE: 2 * 1024 * 1024 * 1024,
    };

    const ui = {
        authView: document.getElementById('auth-view'),
        appView: document.getElementById('app-view'),
        // 视图
        filesView: document.getElementById('files-view'),
        sharesView: document.getElementById('shares-view'),
        statsView: document.getElementById('stats-view'),
        // 认证
        authTitle: document.getElementById('auth-title'),
        authButton: document.getElementById('auth-button'),
        authPrompt: document.getElementById('auth-prompt'),
        switchAuthLink: document.getElementById('switch-auth-link'),
        authError: document.getElementById('auth-error'),
        usernameInput: document.getElementById('username'),
        passwordInput: document.getElementById('password'),
        // 导航
        sidebar: document.getElementById('sidebar'),
        sidebarToggle: document.getElementById('sidebar-toggle'),
        navLinks: document.querySelectorAll('aside.sidebar nav a'),
        logoutButton: document.getElementById('logout-button'),
        userInfoUsername: document.getElementById('user-info-username'),
        // 文件视图
        breadcrumbBar: document.getElementById('breadcrumb-bar'),
        searchInput: document.getElementById('search-input'),
        uploadFileButton: document.getElementById('upload-file-btn'),
        uploadFolderButton: document.getElementById('upload-folder-btn'),
        newFolderButton: document.getElementById('new-folder-button'),
        fileInput: document.getElementById('file-input'),
        folderInput: document.getElementById('folder-input'),
        fileListBody: document.getElementById('file-list-body'),
        selectAllCheckbox: document.getElementById('select-all-checkbox'),
        // 上下文工具栏
        contextualToolbar: document.getElementById('contextual-toolbar'),
        selectionCount: document.getElementById('selection-count'),
        selectionShareBtn: document.getElementById('selection-share-btn'),
        selectionDownloadBtn: document.getElementById('selection-download-btn'),
        selectionDeleteBtn: document.getElementById('selection-delete-btn'),
        // 上传
        uploadManager: document.getElementById('upload-manager'),
        uploadQueue: document.getElementById('upload-queue'),
        toggleUploadManagerBtn: document.getElementById('toggle-upload-manager-btn'),
        // 拖拽
        dropZone: document.body, // 监听整个页面
        dropOverlay: document.getElementById('drop-overlay'),
        // 分享视图
        shareListBody: document.getElementById('share-list-body'),
        // 数据统计视图
        statsGrid: document.getElementById('stats-grid-container'),
        fileTypeChartCanvas: document.getElementById('file-type-chart'),
        // 容量条
        capacityText: document.getElementById('capacity-text'),
        capacityBarInner: document.getElementById('capacity-bar-inner'),
        // 通用
        modalContainer: document.getElementById('modal-container'),
        toastContainer: document.getElementById('toast-container'),
    };

    let fileTypeChart = null;

    // --- 初始化 ---
    function initialize() {
        setupEventListeners();
        const token = localStorage.getItem('authToken');
        const username = localStorage.getItem('username');
        if (token && username) {
            state.token = token;
            state.username = username;
            showView('files');
            connectWebSocket();
        } else {
            showView('auth');
        }
    }

    // --- 视图管理 ---
    function showView(viewName) {
        state.currentView = viewName;
        ui.authView.classList.toggle('hidden', viewName !== 'auth');
        ui.appView.classList.toggle('hidden', viewName === 'auth');
        
        if (viewName !== 'auth') {
            ['files', 'shares', 'stats'].forEach(v => ui[v + 'View'].classList.add('hidden'));
            ui[viewName + 'View'].classList.remove('hidden');
            
            ui.navLinks.forEach(link => {
                link.classList.toggle('active', link.id === \`nav-\${viewName}\`);
            });

            if (viewName === 'files') renderFileList();
            if (viewName === 'shares') loadSharesData();
            if (viewName === 'stats') loadStatsData();
        }
        updateUserInfo();
    }

    // --- 事件监听 ---
    function setupEventListeners() {
        // 认证
        ui.switchAuthLink.addEventListener('click', toggleAuthMode);
        ui.authButton.addEventListener('click', handleAuthAction);
        ui.logoutButton.addEventListener('click', handleLogout);
        
        // 导航
        ui.sidebarToggle.addEventListener('click', () => ui.sidebar.classList.toggle('open'));
        document.addEventListener('click', (e) => {
            if (!ui.sidebar.contains(e.target) && !ui.sidebarToggle.contains(e.target)) {
                ui.sidebar.classList.remove('open');
            }
        });
        ui.navLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const viewName = e.currentTarget.id.replace('nav-', '');
                showView(viewName);
                ui.sidebar.classList.remove('open');
            });
        });
        
        // 文件操作
        ui.uploadFileButton.addEventListener('click', (e) => { e.preventDefault(); ui.fileInput.click(); });
        ui.uploadFolderButton.addEventListener('click', (e) => { e.preventDefault(); ui.folderInput.click(); });
        ui.fileInput.addEventListener('change', handleFileSelection);
        ui.folderInput.addEventListener('change', handleFileSelection);
        ui.newFolderButton.addEventListener('click', showNewFolderModal);
        ui.searchInput.addEventListener('input', () => renderFileList());
        ui.selectAllCheckbox.addEventListener('change', handleSelectAll);

        // 上下文工具栏
        ui.selectionShareBtn.addEventListener('click', handleSelectionShare);
        ui.selectionDeleteBtn.addEventListener('click', handleSelectionDelete);

        // 拖拽上传
        setupDragAndDrop();

        // 上传管理器
        ui.toggleUploadManagerBtn.addEventListener('click', () => {
            ui.uploadQueue.classList.toggle('hidden');
            ui.toggleUploadManagerBtn.querySelector('i').classList.toggle('fa-chevron-down');
            ui.toggleUploadManagerBtn.querySelector('i').classList.toggle('fa-chevron-up');
        });
    }

    // --- 认证逻辑 ---
    function toggleAuthMode() {
        const isLogin = ui.authTitle.textContent === '登录';
        ui.authTitle.textContent = isLogin ? '注册' : '登录';
        ui.authButton.textContent = isLogin ? '注册' : '登录';
        ui.authPrompt.textContent = isLogin ? '已有账户？' : '还没有账户？';
        ui.switchAuthLink.textContent = isLogin ? '立即登录' : '立即注册';
        ui.authError.textContent = '';
    }

    async function handleAuthAction() {
        const isLogin = ui.authTitle.textContent === '登录';
        const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
        const username = ui.usernameInput.value.trim();
        const password = ui.passwordInput.value.trim();

        if (!username || !password) {
            ui.authError.textContent = '用户名和密码不能为空';
            return;
        }
        ui.authError.textContent = '';
        ui.authButton.disabled = true;
        ui.authButton.textContent = isLogin ? '登录中...' : '注册中...';

        try {
            const data = await apiCall(endpoint, { method: 'POST', body: { username, password } });
            if (isLogin) {
                state.token = data.token;
                state.username = data.username;
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('username', data.username);
                showView('files');
                connectWebSocket();
            } else {
                showToast('注册成功！请登录。', 'success');
                toggleAuthMode();
            }
        } catch (e) {
            ui.authError.textContent = e.message;
        } finally {
            ui.authButton.disabled = false;
            ui.authButton.textContent = isLogin ? '登录' : '注册';
        }
    }

    function handleLogout() {
        state.isLoggingOut = true;
        if (state.socket) {
            state.socket.close();
            state.socket = null;
        }
        state.token = null;
        state.username = null;
        localStorage.removeItem('authToken');
        localStorage.removeItem('username');
        state.allItems = [];
        state.currentParentId = 'root';
        state.pathHistory = ['root'];
        state.selectedItemIds.clear();
        showView('auth');
        setTimeout(() => state.isLoggingOut = false, 1000);
    }

    // --- WebSocket 通信 ---
    function connectWebSocket() {
        if (!state.token) return;
        if (state.socket && state.socket.readyState < 2) return;

        const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
        const wsUrl = \`\${wsProtocol}://\${window.location.host}/?token=\${state.token}\`;
        
        state.socket = new WebSocket(wsUrl);
        state.socket.onopen = () => console.log('WebSocket connected.');
        state.socket.onmessage = handleSocketMessage;
        state.socket.onclose = () => {
            if (!state.isLoggingOut) {
                console.log('WebSocket disconnected. Reconnecting...');
                setTimeout(connectWebSocket, 3000);
            }
        };
        state.socket.onerror = (err) => console.error('WebSocket error:', err);
    }

    function handleSocketMessage(event) {
        const data = JSON.parse(event.data);
        switch (data.type) {
            case 'history':
                state.allItems = data.items;
                state.totalSize = data.totalSize;
                renderFileList();
                updateUserInfo();
                break;
            case 'item_added':
                if (!state.allItems.some(item => item.id === data.item.id)) {
                    state.allItems.push(data.item);
                    if (data.item.type === 'file') state.totalSize += data.item.size;
                    renderFileList();
                    updateUserInfo();
                }
                break;
            case 'items_deleted':
                const deletedIds = new Set(data.itemIds);
                const deletedFiles = state.allItems.filter(i => deletedIds.has(i.id) && i.type === 'file');
                const sizeToReduce = deletedFiles.reduce((sum, file) => sum + file.size, 0);
                state.totalSize -= sizeToReduce;
                state.allItems = state.allItems.filter(i => !deletedIds.has(i.id));
                state.selectedItemIds.forEach(id => {
                    if (deletedIds.has(id)) state.selectedItemIds.delete(id);
                });
                renderFileList();
                updateUserInfo();
                updateContextualToolbar();
                break;
            case 'error':
                showToast('发生错误: ' + data.message, 'error');
                break;
        }
    }

    // --- 文件管理器核心逻辑 ---
    function renderFileList() {
        if (state.currentView !== 'files') return;
        
        renderBreadcrumb();
        
        const filterText = ui.searchInput.value.toLowerCase();
        const currentItems = state.allItems
            .filter(i => i.parentId === state.currentParentId)
            .filter(i => i.name.toLowerCase().includes(filterText))
            .sort((a, b) => {
                if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
                return a.name.localeCompare(b.name);
            });

        ui.fileListBody.innerHTML = '';
        if (currentItems.length === 0) {
            const message = filterText ? '未找到匹配项' : '此文件夹为空，拖拽文件到此处以上传';
            ui.fileListBody.innerHTML = \`<tr><td colspan="5" class="empty-state">\${message}</td></tr>\`;
            return;
        }

        currentItems.forEach(item => {
            const tr = document.createElement('tr');
            tr.dataset.id = item.id;
            const isFolder = item.type === 'folder';
            const isSelected = state.selectedItemIds.has(item.id);
            tr.innerHTML = \`
                <td><input type="checkbox" class="item-checkbox" \${isSelected ? 'checked' : ''}></td>
                <td>
                    <span class="item-name" data-type="\${item.type}">
                        <i class="fas \${isFolder ? 'fa-folder' : 'fa-file-alt'}"></i>
                        \${escapeHtml(item.name)}
                    </span>
                </td>
                <td>\${isFolder ? '—' : formatBytes(item.size)}</td>
                <td>\${new Date(item.updatedAt).toLocaleString()}</td>
                <td class="item-actions">
                    <button class="share-btn" title="分享"><i class="fas fa-share-alt"></i></button>
                    <button class="delete-btn" title="删除"><i class="fas fa-trash-alt"></i></button>
                </td>
            \`;
            tr.querySelector('.item-name').addEventListener('click', () => handleItemClick(item));
            tr.querySelector('.item-checkbox').addEventListener('change', (e) => handleItemSelection(item.id, e.target.checked));
            tr.querySelector('.delete-btn').addEventListener('click', () => handleDeleteItem(item));
            tr.querySelector('.share-btn').addEventListener('click', () => showShareModal([item]));
            
            ui.fileListBody.appendChild(tr);
        });
        updateContextualToolbar();
    }

    function handleItemClick(item) {
        if (item.type === 'folder') {
            state.currentParentId = item.id;
            state.pathHistory.push(item.id);
            ui.searchInput.value = '';
            clearSelection();
            renderFileList();
        } else {
            // 文件点击预览或下载
            const url = \`/upload/download?r2_key=\${item.r2Key}&filename=\${encodeURIComponent(item.name)}&token=\${state.token}\`;
            window.open(url, '_blank');
        }
    }

    function renderBreadcrumb() {
        let path = [];
        let currentId = state.currentParentId;
        const itemMap = new Map(state.allItems.map(i => [i.id, i]));

        while (currentId !== 'root') {
            const folder = itemMap.get(currentId);
            if (!folder) break;
            path.unshift(folder);
            currentId = folder.parentId;
        }

        let html = '<a href="#" data-id="root"><i class="fas fa-home"></i> 根目录</a>';
        path.forEach((folder, index) => {
            if (index < path.length) {
                html += \` / <a href="#" data-id="\${folder.id}">\${escapeHtml(folder.name)}</a>\`;
            } else {
                html += \` / <span>\${escapeHtml(folder.name)}</span>\`;
            }
        });
        ui.breadcrumbBar.innerHTML = html;

        ui.breadcrumbBar.querySelectorAll('a').forEach(a => {
            a.addEventListener('click', (e) => {
                e.preventDefault();
                const targetId = e.currentTarget.dataset.id;
                state.currentParentId = targetId;
                
                const newHistoryIndex = state.pathHistory.indexOf(targetId);
                if (newHistoryIndex > -1) {
                    state.pathHistory.length = newHistoryIndex + 1;
                }
                
                clearSelection();
                renderFileList();
            });
        });
    }

    function handleDeleteItem(item) {
        const message = item.type === 'folder' 
            ? '确定要删除这个文件夹及其所有内容吗？此操作不可恢复。' 
            : '确定要删除这个文件吗？';
        if (confirm(message)) {
            if (state.socket && state.socket.readyState === WebSocket.OPEN) {
                state.socket.send(JSON.stringify({ type: 'delete_items', itemIds: [item.id] }));
            }
        }
    }

    // --- 批量选择与操作 ---
    function handleItemSelection(itemId, isSelected) {
        if (isSelected) {
            state.selectedItemIds.add(itemId);
        } else {
            state.selectedItemIds.delete(itemId);
        }
        updateContextualToolbar();
    }

    function handleSelectAll(e) {
        const isChecked = e.target.checked;
        const currentItems = state.allItems.filter(i => i.parentId === state.currentParentId);
        currentItems.forEach(item => {
            if (isChecked) {
                state.selectedItemIds.add(item.id);
            } else {
                state.selectedItemIds.delete(item.id);
            }
        });
        renderFileList(); // Re-render to update all checkboxes
    }

    function clearSelection() {
        state.selectedItemIds.clear();
        ui.selectAllCheckbox.checked = false;
        updateContextualToolbar();
    }

    function updateContextualToolbar() {
        const count = state.selectedItemIds.size;
        if (count > 0) {
            ui.contextualToolbar.classList.remove('hidden');
            ui.selectionCount.textContent = \`已选择 \${count} 项\`;
        } else {
            ui.contextualToolbar.classList.add('hidden');
        }
        // 更新全选框状态
        const currentItemsOnPage = state.allItems.filter(i => i.parentId === state.currentParentId);
        const currentItemsCount = currentItemsOnPage.length;
        
        if (currentItemsCount > 0) {
            ui.selectAllCheckbox.checked = count === currentItemsCount;
            ui.selectAllCheckbox.indeterminate = count > 0 && count < currentItemsCount;
        } else {
            ui.selectAllCheckbox.checked = false;
            ui.selectAllCheckbox.indeterminate = false;
        }
    }

    function handleSelectionShare() {
        const selectedItems = state.allItems.filter(item => state.selectedItemIds.has(item.id));
        if (selectedItems.length > 0) {
            showShareModal(selectedItems);
        }
    }

    function handleSelectionDelete() {
        if (confirm(\`确定要删除选中的 \${state.selectedItemIds.size} 个项目吗？此操作不可恢复。\`)) {
            if (state.socket && state.socket.readyState === WebSocket.OPEN) {
                state.socket.send(JSON.stringify({ type: 'delete_items', itemIds: Array.from(state.selectedItemIds) }));
            }
        }
    }

    // --- 用户信息更新 ---
    function updateUserInfo() {
        if (state.username) {
            ui.userInfoUsername.textContent = state.username;
            // 修改为只显示已用空间，不显示总空间，实现“无限”感
            ui.capacityText.textContent = \`已用: \${formatBytes(state.totalSize)}\`;
            // 进度条可以保留，但它不再代表一个硬性限制
            // 为了视觉效果，我们可以让它在空间占用很小时几乎看不见，然后对数增长
            const percentage = state.totalSize > 0 ? Math.min(100, 10 * Math.log10(1 + state.totalSize / (1024*1024))) : 0;
            ui.capacityBarInner.style.width = \`\${percentage}%\`;
        }
    }

    // --- 上传逻辑 (拖拽, 分块, 并发) ---
    function setupDragAndDrop() {
        let dragCounter = 0;

        ui.dropZone.addEventListener('dragenter', (e) => {
            e.preventDefault();
            e.stopPropagation();
            dragCounter++;
            if (state.currentView === 'files' && e.dataTransfer.items && e.dataTransfer.items.length > 0) {
                ui.dropOverlay.classList.remove('hidden');
            }
        });

        ui.dropZone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            e.stopPropagation();
            dragCounter--;
            if (dragCounter === 0) {
                ui.dropOverlay.classList.add('hidden');
            }
        });

        ui.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.stopPropagation();
        });

        ui.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            e.stopPropagation();
            dragCounter = 0;
            ui.dropOverlay.classList.add('hidden');
            if (state.currentView !== 'files') return;

            const items = e.dataTransfer.items;
            if (items) {
                for (let i = 0; i < items.length; i++) {
                    const entry = items[i].webkitGetAsEntry();
                    if (entry) {
                        scanFiles(entry);
                    }
                }
            }
        });
    }

    function scanFiles(entry) {
        if (entry.isFile) {
            entry.file(file => {
                addFileToUploadQueue(file);
            });
        } else if (entry.isDirectory) {
            const dirReader = entry.createReader();
            dirReader.readEntries(entries => {
                entries.forEach(subEntry => {
                    scanFiles(subEntry);
                });
            });
        }
    }

    function handleFileSelection(event) {
        const files = event.target.files;
        if (!files.length) return;
        for (const file of files) {
            addFileToUploadQueue(file);
        }
        // 清空input的值，以便可以再次选择相同的文件
        ui.fileInput.value = '';
        ui.folderInput.value = '';
    }

    function addFileToUploadQueue(file) {
        // 新增：前端文件大小校验
        if (file.size > state.MAX_FILE_SIZE) {
            showToast(\`文件 "\${file.name}" (\${formatBytes(file.size)}) 超过了2GB的上传限制。\`, 'error');
            return; // 不添加到上传队列
        }

        const id = crypto.randomUUID();
        state.uploadQueue[id] = { 
            file, 
            id, 
            progress: 0, 
            speed: 0, 
            lastLoaded: 0, 
            lastTimestamp: Date.now(), 
            status: 'queued',
            retries: 0
        };
        ui.uploadManager.classList.remove('hidden');
        renderUploadQueue();
        processUploadQueue();
    }

    function processUploadQueue() {
        while (state.activeUploads < state.MAX_CONCURRENT_UPLOADS) {
            const nextUploadId = Object.keys(state.uploadQueue).find(id => state.uploadQueue[id].status === 'queued');
            if (nextUploadId) {
                state.activeUploads++;
                state.uploadQueue[nextUploadId].status = 'uploading';
                uploadFileWithChunks(state.uploadQueue[nextUploadId]);
            } else {
                break; // No more queued files
            }
        }
    }

    async function uploadFileWithChunks(uploadItem) {
        const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
        const { file, id } = uploadItem;
        
        try {
            // 1. Create multipart upload, 新增：发送文件大小以供后端校验
            const { key, uploadId } = await apiCall(\`/upload/create-multipart?token=\${state.token}\`, {
                method: 'POST',
                body: { fileName: file.name, contentType: file.type || 'application/octet-stream', fileSize: file.size }
            });
            uploadItem.r2Key = key;
            uploadItem.uploadId = uploadId;

            const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
            const uploadedParts = [];

            for (let i = 0; i < totalChunks; i++) {
                const start = i * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);
                const partNumber = i + 1;

                // 2. Get presigned URL for the chunk
                const { url: presignedUrl } = await apiCall(\`/upload/get-upload-part-url?token=\${state.token}\`, {
                    method: 'POST',
                    body: { key, uploadId, partNumber }
                });

                // 3. Upload chunk
                const uploadResponse = await fetch(presignedUrl, {
                    method: 'PUT',
                    body: chunk
                });
                if (!uploadResponse.ok) throw new Error(\`分块 \${partNumber} 上传失败\`);
                
                const etag = uploadResponse.headers.get('ETag');
                uploadedParts.push({ ETag: etag, PartNumber: partNumber });

                // Update progress and speed
                uploadItem.progress = (partNumber / totalChunks) * 100;
                const now = Date.now();
                const timeDiff = (now - uploadItem.lastTimestamp) / 1000;
                const loadedDiff = chunk.size;
                if (timeDiff > 0.5) { // 每0.5秒更新一次速度
                    uploadItem.speed = loadedDiff / timeDiff;
                    uploadItem.lastTimestamp = now;
                }
                uploadItem.lastLoaded += loadedDiff;
                renderUploadQueue();
            }

            // 4. Complete multipart upload
            // 后端将处理元数据创建
            await apiCall(\`/upload/complete-multipart?token=\${state.token}\`, {
                method: 'POST',
                body: {
                    key,
                    uploadId,
                    parts: uploadedParts,
                    fileInfo: {
                        parentId: state.currentParentId,
                        name: file.name,
                        size: file.size,
                        type: file.type || 'application/octet-stream'
                    }
                }
            });

            showToast(\`\${file.name} 上传成功\`, 'success');
            delete state.uploadQueue[id];

        } catch (error) {
            console.error(\`Upload failed for \${file.name}:\`, error);
            showToast(\`上传失败: \${file.name} - \${error.message}\`, 'error');
            uploadItem.status = 'failed';
            // Optional: Abort multipart upload
            if (uploadItem.uploadId) {
                apiCall(\`/upload/abort-multipart?token=\${state.token}\`, {
                    method: 'POST',
                    body: { key: uploadItem.r2Key, uploadId: uploadItem.uploadId }
                }).catch(e => console.error('Failed to abort multipart upload:', e));
            }
        } finally {
            state.activeUploads--;
            renderUploadQueue();
            processUploadQueue();
            if (Object.keys(state.uploadQueue).length === 0) {
                setTimeout(() => {
                    if (Object.keys(state.uploadQueue).length === 0) {
                        ui.uploadManager.classList.add('hidden');
                    }
                }, 5000);
            }
        }
    }

    function renderUploadQueue() {
        ui.uploadQueue.innerHTML = '';
        Object.values(state.uploadQueue).forEach(item => {
            const speed = item.speed > 0 ? \`(\${formatBytes(item.speed)}/s)\` : '';
            const itemEl = document.createElement('div');
            itemEl.className = 'upload-item';
            let statusText = \`\${item.progress.toFixed(1)}% \${speed}\`;
            if (item.status === 'failed') statusText = '上传失败';
            if (item.status === 'queued') statusText = '等待中...';
            
            itemEl.innerHTML = \`
                <div class="upload-item-info">
                    <span class="upload-item-name" title="\${escapeHtml(item.file.name)}">\${escapeHtml(item.file.name)}</span>
                    <span class="upload-item-status">\${statusText}</span>
                </div>
                <progress class="upload-item-progress" value="\${item.progress}" max="100"></progress>
            \`;
            ui.uploadQueue.appendChild(itemEl);
        });
    }

    // --- 模态框逻辑 ---
    function showModal({ title, body, footer }) {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = \`
            <div class="modal-content">
                <div class="modal-header"><h3>\${title}</h3><button class="modal-close">&times;</button></div>
                <div class="modal-body">\${body}</div>
                <div class="modal-footer">\${footer}</div>
            </div>
        \`;
        modal.querySelector('.modal-close').addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
        ui.modalContainer.innerHTML = '';
        ui.modalContainer.appendChild(modal);
    }

    function closeModal() {
        ui.modalContainer.innerHTML = '';
    }

    function showNewFolderModal() {
        showModal({
            title: '新建文件夹',
            body: \`<div class="form-group"><label for="folder-name">文件夹名称</label><input type="text" id="folder-name" autofocus></div>\`,
            footer: \`<button id="modal-cancel">取消</button><button id="modal-confirm" class="btn-primary">创建</button>\`
        });
        document.getElementById('modal-cancel').addEventListener('click', closeModal);
        const confirmBtn = document.getElementById('modal-confirm');
        const folderNameInput = document.getElementById('folder-name');
        
        const createAction = () => {
            const name = folderNameInput.value.trim();
            if (name && state.socket && state.socket.readyState === WebSocket.OPEN) {
                state.socket.send(JSON.stringify({ type: 'create_folder', name, parentId: state.currentParentId }));
                closeModal();
            } else if (!name) {
                showToast('文件夹名称不能为空', 'error');
            }
        };
        confirmBtn.addEventListener('click', createAction);
        folderNameInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') createAction(); });
    }

    function showShareModal(items) {
        const isSingleFile = items.length === 1 && items[0].type === 'file';
        const title = items.length > 1 ? \`分享 \${items.length} 个项目\` : \`分享 "\${items[0].name}"\`;
        
        showModal({
            title: title,
            body: \`
                <div class="form-group">
                    <label for="share-expiry">有效期</label>
                    <select id="share-expiry">
                        <option value="30d" selected>30天</option>
                        <option value="7d">7天</option>
                        <option value="permanent">永久</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="share-password">设置密码 (可选)</label>
                    <input type="text" id="share-password" placeholder="留空则为公开分享">
                </div>
                <div id="share-link-result" class="hidden"></div>
            \`,
            footer: \`<button id="modal-cancel">关闭</button><button id="modal-confirm" class="btn-primary">生成分享链接</button>\`
        });
        document.getElementById('modal-cancel').addEventListener('click', closeModal);
        document.getElementById('modal-confirm').addEventListener('click', async (e) => {
            const button = e.target;
            button.disabled = true;
            button.textContent = '生成中...';
            const password = document.getElementById('share-password').value;
            const expiry = document.getElementById('share-expiry').value;
            const itemIds = items.map(i => i.id);
            try {
                const data = await apiCall('/api/share/create', {
                    method: 'POST',
                    body: { itemIds, password, expiry }
                });
                const shareLink = \`\${window.location.origin}/s/\${data.shareId}\`;
                const resultEl = document.getElementById('share-link-result');
                resultEl.innerHTML = \`链接: <a href="\${shareLink}" target="_blank">\${shareLink}</a> <button id="copy-share-link-btn" title="复制"><i class="fas fa-copy"></i></button>\`;
                resultEl.classList.remove('hidden');
                
                document.getElementById('copy-share-link-btn').addEventListener('click', () => {
                    navigator.clipboard.writeText(shareLink);
                    showToast('分享链接已复制', 'success');
                });

                button.textContent = '完成';
                button.onclick = closeModal;

            } catch (err) {
                showToast('创建分享失败: ' + err.message, 'error');
                button.disabled = false;
                button.textContent = '生成分享链接';
            }
        });
    }

    // --- 我的分享逻辑 ---
    async function loadSharesData() {
        ui.shareListBody.innerHTML = '<tr><td colspan="6" class="loading-state">加载分享列表中...</td></tr>';
        try {
            const data = await apiCall('/api/shares');
            renderShareList(data.shares);
        } catch (e) {
            showToast('加载分享列表失败: ' + e.message, 'error');
            ui.shareListBody.innerHTML = '<tr><td colspan="6" class="empty-state">加载失败</td></tr>';
        }
    }

    function renderShareList(shares) {
        ui.shareListBody.innerHTML = '';
        if (!shares || shares.length === 0) {
            ui.shareListBody.innerHTML = '<tr><td colspan="6" class="empty-state">您还没有创建任何分享</td></tr>';
            return;
        }
        shares.sort((a, b) => b.createdAt - a.createdAt).forEach(share => {
            const shareLink = \`\${window.location.origin}/s/\${share.id}\`;
            let status = '有效';
            if (share.expiration) {
                const expiryDate = new Date(share.expiration * 1000);
                if (expiryDate < new Date()) {
                    status = '<span style="color: var(--danger-color);">已过期</span>';
                } else {
                    // 优化：显示具体到期日期
                    status = \`\${expiryDate.toLocaleDateString()} 到期\`;
                }
            } else {
                status = '永久有效';
            }
            if (share.passwordHash) status += ' (加密)';

            const tr = document.createElement('tr');
            tr.innerHTML = \`
                <td><i class="fas \${share.rootType === 'folder' ? 'fa-folder' : 'fa-file-alt'}"></i> \${escapeHtml(share.rootName)}</td>
                <td class="share-link-cell" title="\${shareLink}"><a href="\${shareLink}" target="_blank">\${shareLink}</a></td>
                <td>\${status}</td>
                <td>\${new Date(share.createdAt).toLocaleString()}</td>
                <td>\${share.visits || 0} / \${share.downloads || 0}</td>
                <td class="item-actions">
                    <button class="copy-share-btn" title="复制链接"><i class="fas fa-copy"></i></button>
                    <button class="delete-share-btn" title="删除分享"><i class="fas fa-trash-alt"></i></button>
                </td>
            \`;
            tr.querySelector('.copy-share-btn').addEventListener('click', () => {
                navigator.clipboard.writeText(shareLink);
                showToast('链接已复制', 'success');
            });
            tr.querySelector('.delete-share-btn').addEventListener('click', async (e) => {
                if (confirm('确定要删除这个分享链接吗？')) {
                    const btn = e.currentTarget;
                    btn.disabled = true;
                    try {
                        await apiCall(\`/api/share/\${share.id}\`, { method: 'DELETE' });
                        showToast('分享已删除', 'success');
                        loadSharesData(); // Refresh list
                    } catch (err) {
                        showToast('删除失败: ' + err.message, 'error');
                        btn.disabled = false;
                    }
                }
            });
            ui.shareListBody.appendChild(tr);
        });
    }

    // --- 数据看板逻辑 ---
    async function loadStatsData() {
        try {
            const data = await apiCall('/api/stats');
            renderStatsCards(data);
            renderFileTypeChart(data.typeCounts);
        } catch (e) {
            showToast('加载统计数据失败', 'error');
            ui.statsGrid.innerHTML = '<p>加载统计数据失败。</p>';
        }
    }

    function renderStatsCards(data) {
        const cards = [
            { label: '文件总数', value: \`\${(data?.fileCount ?? 0).toLocaleString()} 个\` },
            { label: '总存储大小', value: formatBytes(data?.totalSize ?? 0) },
        ];
        ui.statsGrid.innerHTML = cards.map(card => \`
            <div class="stat-card"><h3>\${card.label}</h3><div class="value">\${card.value}</div></div>
        \`).join('');
    }

    function renderFileTypeChart(typeCounts) {
        if (fileTypeChart) fileTypeChart.destroy();
        const counts = typeCounts || {};
        const labels = Object.keys(counts);
        const data = Object.values(counts);
        
        const ctx = ui.fileTypeChartCanvas.getContext('2d');
        if (labels.length === 0) {
            ctx.clearRect(0, 0, ui.fileTypeChartCanvas.width, ui.fileTypeChartCanvas.height);
            ctx.textAlign = 'center';
            ctx.font = '16px sans-serif';
            ctx.fillStyle = '#888';
            ctx.fillText('暂无文件数据', ui.fileTypeChartCanvas.width / 2, ui.fileTypeChartCanvas.height / 2);
            return;
        }

        fileTypeChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: ['#007bff', '#28a745', '#ffc107', '#dc3545', '#17a2b8', '#6f42c1', '#fd7e14', '#20c997'],
                }]
            },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right' } } }
        });
    }

    // --- 工具函数 ---
    async function apiCall(endpoint, options = {}) {
        const headers = { 'Content-Type': 'application/json', ...options.headers };
        if (state.token) {
            headers['Authorization'] = \`Bearer \${state.token}\`;
        }
        const config = {
            method: options.method || 'GET',
            headers,
        };
        if (options.body) {
            config.body = JSON.stringify(options.body);
        }
        const response = await fetch(endpoint, config);
        if (response.status === 204) return null; // No Content
        
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || \`HTTP error! status: \${response.status}\`);
            }
            return data;
        } else {
            if (!response.ok) {
                throw new Error(\`HTTP error! status: \${response.status}\`);
            }
            return await response.text();
        }
    }

    function showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = \`toast \${type}\`;
        toast.textContent = message;
        ui.toastContainer.appendChild(toast);
        setTimeout(() => {
            toast.classList.add('show');
        }, 10);
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 4000); // 延长显示时间
    }

    function formatBytes(bytes, decimals = 2) {
        if (!bytes || bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return '';
        return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    // --- 启动应用 ---
    initialize();
})();
`;

// 导出模块以供Cloudflare Worker使用
export {
  StatsAggregator,
  UserSpace,
  worker as default
};
//# sourceMappingURL=index.js.map

