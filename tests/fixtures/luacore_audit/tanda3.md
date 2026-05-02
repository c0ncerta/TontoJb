# Fixture: new PT guard blocks slow RW

[+] INYECTADO: poopsploit_chain.js (81234 bytes) sha256=3333333333333333333333333333333333333333333333333333333333333333
[1] === RACE WON! ===
[1] pair=31,32
[PT] phase twins -> ready reason=distinct_master_slave_pair
[PT] phase reclaim -> ready reason=marker_round_1_spray_4
[K2] *** RECLAIM HIT! marker=0xcafe0004 spray[4] fd=44 ***
[PT] phase triplet -> planned reason=not_implemented_in_knote_path
[PT] phase slow_rw -> blocked reason=triplet_not_ready
[SUMMARY] R/W primitive blocked: triplet invariant missing
[PT] summary twins=ready reclaim=ready triplet=planned kaslr=failed slow_rw=blocked
