from collections import deque
from detection.graph_builder import build_graph

def get_hotspots(root_dir: str, top_n: int = 15):
    graph = build_graph(root_dir)

    visited = set()
    queue = deque([root_dir])
    bfs_nodes = []

    while queue:
        current = queue.popleft()

        if current in visited:
            continue

        visited.add(current)

        if current in graph:
            bfs_nodes.append((current, graph.nodes[current]))

        for neighbor in graph.successors(current):
            if neighbor not in visited:
                queue.append(neighbor)

    hotspots = sorted(
        bfs_nodes,
        key=lambda x: x[1].get("weight", 0),
        reverse=True
    )[:top_n]

    return [path for path, data in hotspots]


if __name__ == "__main__":
    root = "/home"

    hotspots = get_hotspots(root, top_n=15)

    print("Top 15 hotspot directories:")
    for path in hotspots:
        print(path)
