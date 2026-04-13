import os
import time
import networkx as nx

def build_graph(root_dir: str):
    graph = nx.DiGraph()
    now = time.time()

    for current_dir, subdirs, files in os.walk(root_dir):
        file_count = len(files)

        mtimes = []
        for f in files:
            full_path = os.path.join(current_dir, f)
            try:
                mtimes.append(os.path.getmtime(full_path))
            except OSError:
                pass

        if mtimes:
            mean_mtime = sum(mtimes) / len(mtimes)
            age = max(0, now - mean_mtime)
            recency_score = 1 / (1 + age / 86400)  
        else:
            recency_score = 0.0

        weight = file_count * 0.6 + recency_score * 0.4

        graph.add_node(
            current_dir,
            file_count=file_count,
            recency_score=recency_score,
            weight=weight
        )

        parent = os.path.dirname(current_dir)
        if parent and parent != current_dir and os.path.exists(parent):
            graph.add_edge(parent, current_dir)

    return graph


if __name__ == "__main__":
    root = "/home"

    g = build_graph(root)

    print("Nodes:", len(g.nodes()))
    print("Edges:", len(g.edges()))

    top_nodes = sorted(
        g.nodes(data=True),
        key=lambda x: x[1].get("weight", 0),
        reverse=True
    )[:15]

    print("\nTop 15 weighted folders:")
    for path, data in top_nodes:
        print(path)
