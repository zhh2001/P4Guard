table_claer ipv4_lpm
table_set_default ipv4_lpm drop

table_claer ipv4_dpi_lpm
table_set_default ipv4_dpi_lpm drop

table_clear src_entropy_term

table_clear dst_entropy_term

table_claer rule_tbl
table_set_default rule_tbl NoAction
table_add rule_tbl flow_control 10.0.0.2 => 1 1 1 10 1 1 1000000

register_write src_ewma  0 2500001
register_write dst_ewma  0 2452881
register_write src_ewmmd 0 38953
register_write dst_ewmmd 0 36773

register_write log2_m       0 14
register_write training_len 0 16
register_write alpha        0 20
register_write k            0 28
