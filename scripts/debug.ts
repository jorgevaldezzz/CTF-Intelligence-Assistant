import "dotenv/config";

const url =
  `${process.env.CHROMA_URL ?? "http://localhost:8000"}` +
  `/api/v2/tenants/default_tenant/databases/default_database/collections`;

async function main() {
  const r = await fetch(url);
  const cols = await r.json();

  console.log(cols);
}

main();