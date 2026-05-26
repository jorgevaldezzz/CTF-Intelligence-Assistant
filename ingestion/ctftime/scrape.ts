import fs from "fs/promises";
import path from "path";

const TOPICS = ["ctf-writeup", "ctf-writeups"];
const PER_PAGE = 100;
const MAX_PAGES_PER_TOPIC = 10; // 1000 repo cap per topic
const RAW_DIR = path.resolve("data/raw/ctftime");
const DELAY_MS = 2500; // stay under 30 req/min search limit

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
if (!GITHUB_TOKEN) {
  console.warn("[warn] GITHUB_TOKEN not set — rate limit is 10 req/min for search");
}

const headers: Record<string, string> = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  ...(GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {}),
};

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchPage(topic: string, page: number): Promise<any[]> {
  const url = `https://api.github.com/search/repositories?q=topic:${topic}&sort=updated&order=desc&per_page=${PER_PAGE}&page=${page}`;
  const res = await fetch(url, { headers });

  if (res.status === 403 || res.status === 429) {
    const reset = res.headers.get("X-RateLimit-Reset");
    const waitUntil = reset ? parseInt(reset) * 1000 : Date.now() + 60_000;
    const waitMs = waitUntil - Date.now() + 1000;
    console.log(`[rate-limit] Sleeping ${Math.ceil(waitMs / 1000)}s…`);
    await sleep(waitMs);
    return fetchPage(topic, page); // retry once
  }

  if (!res.ok) throw new Error(`GitHub API ${res.status} on page ${page} of topic:${topic}`);

  const data = await res.json();
  return data.items ?? [];
}

export async function scrapeRepos(): Promise<void> {
  await fs.mkdir(RAW_DIR, { recursive: true });

  const seen = new Set<number>(); // dedupe by repo id across topics
  const allRepos: any[] = [];

  for (const topic of TOPICS) {
    console.log(`[scrape] topic:${topic}`);

    for (let page = 1; page <= MAX_PAGES_PER_TOPIC; page++) {
      const items = await fetchPage(topic, page);
      if (items.length === 0) break;

      let added = 0;
      for (const repo of items) {
        if (!seen.has(repo.id)) {
          seen.add(repo.id);
          allRepos.push({
            id: repo.id,
            full_name: repo.full_name,
            html_url: repo.html_url,
            description: repo.description ?? null,
            topics: repo.topics ?? [],
            stargazers_count: repo.stargazers_count,
            pushed_at: repo.pushed_at,
            default_branch: repo.default_branch ?? "main",
          });
          added++;
        }
      }

      console.log(
        `  page ${page}: ${items.length} results, ${added} new (total ${allRepos.length})`
      );

      if (items.length < PER_PAGE) break; // last page
      await sleep(DELAY_MS);
    }
  }

  const outPath = path.join(RAW_DIR, "repos.json");
  await fs.writeFile(outPath, JSON.stringify(allRepos, null, 2));
  console.log(`[scrape] Saved ${allRepos.length} repos → ${outPath}`);
}