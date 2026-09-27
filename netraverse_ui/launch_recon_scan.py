"""python launch_recon_scan.py  -  Reconnaissance - network service scan (T1046 Network Service Discovery)"""
from _trigger import launch

if __name__ == "__main__":
    launch("recon_scan", "Reconnaissance - network service scan", "T1046 Network Service Discovery", "10.13.37.5", "10.20.0.0/24")
