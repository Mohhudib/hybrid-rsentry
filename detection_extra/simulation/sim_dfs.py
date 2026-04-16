import os, random, string

def random_content(size=4096):
    """Generate high-entropy random bytes to simulate encryption."""
    return os.urandom(size)

def sim_dfs(root_dir: str):
    """
    Simulate ransomware doing DFS traversal.
    Rewrites each file with random bytes and renames to .enc
    Skips AAA_ canary files (real ransomware tries to avoid detection).
    """
    print(f"[SIM_DFS] Starting DFS traversal from {root_dir}")
    count = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.startswith("AAA_")or filename.endswith(".enc"):
                continue  # skip canaries
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, "wb") as f:
                    f.write(random_content())
                enc_path = filepath + ".enc"
                os.rename(filepath, enc_path)
                count += 1
                print(f"[SIM_DFS] Encrypted: {enc_path}")
            except Exception as e:
                print(f"[SIM_DFS] Skipped {filepath}: {e}")
    print(f"[SIM_DFS] Done. {count} files encrypted.")

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sim_test"
    os.makedirs(root, exist_ok=True)
    sim_dfs(root)
