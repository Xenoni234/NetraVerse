"""python launch_brute_force.py  -  Credential Access - SSH brute force (T1110 Brute Force)"""
from _trigger import launch

if __name__ == "__main__":
    launch("brute_force", "Credential Access - SSH brute force", "T1110 Brute Force", "10.13.37.7", "10.20.0.12")
