"""python launch_c2_beacon.py  -  Command & Control - HTTPS beaconing (T1071 Application Layer Protocol)"""
from _trigger import launch

if __name__ == "__main__":
    launch("c2_beacon", "Command & Control - HTTPS beaconing", "T1071 Application Layer Protocol", "10.20.0.14", "10.13.37.8")
