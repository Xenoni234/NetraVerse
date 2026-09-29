"""python stop_attack.py  -  stop every active attack (risk decays in the console)."""
from _trigger import _post

if __name__ == "__main__":
    try:
        _post("all", "stop")
        print("\n  [x] stop signal sent - all active attacks will decay in the console\n")
    except OSError as e:
        print(f"  [!] console not reachable: {e}")
