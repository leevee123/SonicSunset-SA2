# Weighted sample storage digest v1

One run of finalize_weighted_digest_v1.py verified the complete audit's recorded input hashes and summarized stored target selectors. No native or engine code was executed.

Machine result: {"version":1,"result":"passed","weighted_stored_streams":65,"stored_weighted_variant_sequences":{"2":27,"0;2":15,"0":21,"0;1;2":1,"0;1":1},"weighted_packet_count_distribution":{"18":2,"24":4,"12":8,"41":1,"36":1,"5":11,"31":1,"7":6,"6":8,"32":4,"66":1,"4":9,"2":8,"3":10,"17":4,"1":5},"post_declared_following_same_stream_opcodes":{"0xff":65,"0x2c":18},"pooled_weighted_destination_groups":248,"pooled_weighted_destinations_in_more_than_one_stream":248,"source_inputs_verified":6,"native_lookahead_access_established_here":false,"normalization_or_weight_sum_rule_inferred":false,"runtime_order_or_binding_proved":false,"script_runs":"finalize_weighted_digest_v1.py once"}

| Pooled category A | Pooled category B | A unique targets | B unique targets | Numeric intersection |
|---|---|---:|---:|---:|
| 0x23 | 0x29 | 52 | 509 | 52 |
| 0x23 | 0x2c.variant0 | 52 | 248 | 49 |
| 0x23 | 0x2c.variant1 | 52 | 6 | 1 |
| 0x23 | 0x2c.variant2 | 52 | 248 | 49 |
| 0x29 | 0x2c.variant0 | 509 | 248 | 248 |
| 0x29 | 0x2c.variant1 | 509 | 6 | 6 |
| 0x29 | 0x2c.variant2 | 509 | 248 | 248 |
| 0x2c.variant0 | 0x2c.variant1 | 248 | 6 | 6 |
| 0x2c.variant0 | 0x2c.variant2 | 248 | 248 | 248 |
| 0x2c.variant1 | 0x2c.variant2 | 6 | 248 | 6 |

Pooled intersections do not supply any cross-stream execution order, common live scratch binding or initial contents. The earlier audit found zero target intersections between distinct packets within the same stored stream; these statements use different scopes.

Observed real boundaries include weight0 and255. No negative signed weights, weight256 or larger, zero packet count, variant3..127 or destination65535 occurs here. Their absence is bounded to this Sonic bank and does not constrain native supported values.

Every weighted record span exactly fills its declared packet data. The following 28 bytes are preserved as available original file bytes, commonly beginning with the next EOS or packet header. Whether the native pipeline reads any of those bytes, and whether a read is used, must come from the separate original-instruction audit. No weight sum or normalization statistic is computed.

pooled-weighted-target-occurrences.csv retains complete grouped record/packet/stream sites and variant counts for every pooled weighted target. Canonical per-packet and per-record raw bytes remain in weighted-packets.ai.json and the complete CSVs.
