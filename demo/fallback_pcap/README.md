# Fallback PCAP

Record the rehearsed sequence here so it can be replayed through **PCAP Upload**
(or `NV_LIVE_REPLAY_PCAP`) if live capture is unavailable:

    sudo tcpdump -i <iface> -w demo/fallback_pcap/live_demo.pcap host <target-ip>
    NV_I_OWN_THIS_TARGET=yes demo/attack_scripts/run_sequence.sh <target-ip>

PCAPs are small enough to commit; keep one known-good capture of the exact sequence.
