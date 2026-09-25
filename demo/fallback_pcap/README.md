# Fallback PCAP (R12)

Record the rehearsed live attack here so it can be replayed through **PCAP Upload**
(or `NV_LIVE_REPLAY_PCAP`) if live capture fails during judging:

    sudo tcpdump -i <iface> -w demo/fallback_pcap/live_demo.pcap host <lab-target-ip>
    NV_I_OWN_THIS_TARGET=yes demo/attack_scripts/run_sequence.sh <lab-target-ip>

PCAPs are small enough to commit; keep one known-good capture of the exact demo sequence.
