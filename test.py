import ipaddress
 
bfrt.cpu_test.pipe.SwitchIngress.ipv4_host.add_with_send(dst_addr="10.0.0.1", port=133)
bfrt.cpu_test.pipe.SwitchIngress.ipv4_host.add_with_send(dst_addr="10.0.0.2", port=132)

p4 = bfrt.cpu_test.pipe
 
def digest_collect(dev_id, pipe_id, directon, parser_id, session, msg):
    for digest in msg:
        print(digest)
    return 1

p4.SwitchIngressDeparser.digest_a.callback_register(digest_collect)