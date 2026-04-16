import os, shutil
import numpy as np

# per-pid access log: {pid: [dir1, dir2, dir3, ...]}
_access_logs: dict[int, list[str]] = {}

def record_access(pid: int, directory: str):
    """Call this every time a process touches a file — M1 calls this."""
    if pid not in _access_logs:
        _access_logs[pid] = []
    _access_logs[pid].append(directory)

def check_reposition(pid: int, canary_path: str) -> str | None:
    """
    Predict next directory this pid will visit.
    If confidence > 0.6, move canary there.
    Returns new canary path or None if not moved.
    """
    dirs = _access_logs.get(pid, [])
    if len(dirs) < 2:
        return None  # not enough data to predict

    # build list of unique directories
    unique_dirs = list(dict.fromkeys(dirs))
    n = len(unique_dirs)
    dir_index = {d: i for i, d in enumerate(unique_dirs)}

    # build transition matrix
    matrix = np.zeros((n, n), dtype=float)
    for i in range(len(dirs) - 1):
        a = dir_index.get(dirs[i])
        b = dir_index.get(dirs[i + 1])
        if a is not None and b is not None:
            matrix[a][b] += 1

    # normalize rows to get probabilities
    for i in range(n):
        row_sum = matrix[i].sum()
        if row_sum > 0:
            matrix[i] /= row_sum

    # predict from last visited directory
    last_dir = dirs[-1]
    if last_dir not in dir_index:
        return None

    last_idx = dir_index[last_dir]
    row = matrix[last_idx]
    best_idx = int(np.argmax(row))
    confidence = row[best_idx]

    if confidence < 0.6:
        return None  # not confident enough

    predicted_dir = unique_dirs[best_idx]

    # move canary to predicted directory
    if not os.path.exists(predicted_dir):
        return None

    filename = os.path.basename(canary_path)
    new_path = os.path.join(predicted_dir, filename)

    try:
        shutil.move(canary_path, new_path)
        print(f"[REPOSITION] Moved canary to {new_path} (confidence {confidence:.2f})")
        return new_path
    except Exception as e:
        print(f"[REPOSITION ERROR] {e}")
        return None
