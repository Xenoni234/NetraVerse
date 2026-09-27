"""python launch_lateral_movement.py  -  Lateral Movement - remote services (T1021 Remote Services)"""
from _trigger import launch

if __name__ == "__main__":
    launch("lateral_movement", "Lateral Movement - remote services", "T1021 Remote Services", "10.20.0.12", "10.20.0.15")
