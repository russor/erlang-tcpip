
-record(pkt, { sport, dport
             , seq, ack = 0
             , flags = []
             , window = 65535
             , checksum
             , urgent = 0
             , options = []
             , data = <<>> }).
