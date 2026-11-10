import { getGraph, getPaths, listSources, resolveSource } from "@/lib/data";
import { SimNotice, SourceSwitcher } from "@/components/ui";
import PathView from "@/components/PathView";
import { PAGES } from "@/lib/nav";

export const dynamic = "force-dynamic";

export default async function AttackPaths({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const source = await resolveSource((await searchParams).source);
  const [paths, graph, sources] = await Promise.all([getPaths(source), getGraph(source), listSources()]);
  const nodes = Object.fromEntries((graph?.nodes ?? []).map((n) => [String(n.id), n]));
  return (
    <>
      <h1>{PAGES.attackPaths.label}</h1>
      <SourceSwitcher current={source.key} sources={sources} path="/attack-paths" />
      <SimNotice source={source} />
      <p className="muted">單一弱點可能只是中風險，串起來才是高風險。只有「網路可達＋已確認可利用的弱點或有效金鑰」才算完整攻擊鏈；
        純網路連線不算。點節點查看資產資訊。這些路徑用來決定修補優先順序。</p>
      {(paths?.paths ?? []).length === 0 ? <div className="panel">目前沒有完整攻擊鏈。</div>
        : <PathView paths={paths!.paths} nodes={nodes} />}
    </>
  );
}
