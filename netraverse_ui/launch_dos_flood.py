"""python launch_dos_flood.py  -  Impact - service flood (T1498 Network Denial of Service)"""
from _trigger import launch

if __name__ == "__main__":
    launch("dos_flood", "Impact - service flood", "T1498 Network Denial of Service", "10.13.37.11", "10.20.0.11")
