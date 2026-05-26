import fs from "fs/promises";
import path from "path";

const RAW_DIR = path.resolve("data/raw/ctftime");
const DELAY_MS = 800; // contents API is more lenient than search

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const headers: Record<string, string> = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  ...(GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {}),
};

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchReadme(fullName: string, branch: string): Promise<string | null> {
  // GitHub serves the rendered README at this endpoint regardless of filename casing
  const url = `https://api.github.com/repos/${fullName}/readme`;
  const res = await fetch(url, { headers });

  if (res.status === 404) return null; // no README — skip
  if (res.status === 403 || res.status === 429) {
    const reset = res.headers.get("X-RateLimit-Reset");
    const waitMs = reset ? parseInt(reset) * 1000 - Date.now() + 1000 : 60_000;
    console.log(`[rate-limit] Sleeping ${Math.ceil(waitMs / 1000)}s…`);
    await sleep(waitMs);
    return fetchReadme(fullName, branch);
  }
  if (!res.ok) return null;

  const data = await res.json();
  if (data.encoding !== "base64" || !data.content) return null;

  return Buffer.from(data.content, "base64").toString("utf-8");
}

export async function fetchWriteups(): Promise<void> {
  const reposPath = path.join(RAW_DIR, "repos.json");
  const repos: any[] = JSON.parse(await fs.readFile(reposPath, "utf-8"));

  const outDir = path.join(RAW_DIR, "readmes");
  await fs.mkdir(outDir, { recursive: true });

  let fetched = 0;
  let skipped = 0;

  for (const repo of repos) {
    const outPath = path.join(outDir, `${repo.id}.json`);

    // resume-safe: skip already fetched
    try {
      await fs.access(outPath);
      skipped++;
      continue;
    } catch {}

    const readme = await fetchReadme(repo.full_name, repo.default_branch);
    if (!readme || readme.trim().length < 200) {
      // too short to be useful — still write a tombstone so we don't re-fetch
      await fs.writeFile(outPath, JSON.stringify({ id: repo.id, skip: true }));
      skipped++;
    } else {
      await fs.writeFile(
        outPath,
        JSON.stringify({
          id: repo.id,
          full_name: repo.full_name,
          html_url: repo.html_url,
          description: repo.description,
          topics: repo.topics,
          stargazers_count: repo.stargazers_count,
          pushed_at: repo.pushed_at,
          readme,
        })
      );
      fetched++;
    }

    if ((fetched + skipped) % 50 === 0) {
      console.log(`[fetch] ${fetched} fetched, ${skipped} skipped of ${repos.length}`);
    }
    await sleep(DELAY_MS);
  }

  console.log(`[fetch] Done — ${fetched} writeups saved, ${skipped} skipped`);
}
