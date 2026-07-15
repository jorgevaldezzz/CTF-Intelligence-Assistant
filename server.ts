import "dotenv/config";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, resolve } from "node:path";
import { generateAnswer } from "./scripts/eval/generate-answer.js";
import { retrieve } from "./scripts/query.js";

const PORT = Number(process.env.PORT ?? 3000);
const ROOT = resolve("ui");

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

function sendJson(res: import("node:http").ServerResponse, status: number, payload: unknown) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

async function readBody(req: import("node:http").IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    chunks.push(buffer);
    size += buffer.length;
    if (size > 1_000_000) {
      throw new Error("Request body too large");
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function serveStatic(pathname: string, res: import("node:http").ServerResponse) {
  const relativePath = pathname === "/" ? "/index.html" : pathname;
  const filePath = join(ROOT, relativePath.startsWith("/") ? relativePath.slice(1) : relativePath);
  try {
    const data = await readFile(filePath);
    res.writeHead(200, {
      "Content-Type": MIME_TYPES[extname(filePath)] ?? "application/octet-stream",
      "Cache-Control": "no-store",
    });
    res.end(data);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/styles.css")) {
    await serveStatic(url.pathname, res);
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, { ok: true });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/query") {
    try {
      const body = await readBody(req);
      const parsed = JSON.parse(body) as {
        query?: string;
        topK?: number;
        hybrid?: boolean;
      };

      const query = parsed.query?.trim();
      if (!query) {
        sendJson(res, 400, { error: "Query text is required." });
        return;
      }

      const chunks = await retrieve(query, {
        topK: parsed.topK ?? 8,
        hybrid: parsed.hybrid ?? true,
      });
      const answer = await generateAnswer(query, chunks);

      sendJson(res, 200, {
        query,
        answer,
        chunks,
      });
    } catch (error) {
      sendJson(res, 500, {
        error: error instanceof Error ? error.message : "Unknown server error",
      });
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`UI server running at http://localhost:${PORT}`);
});
