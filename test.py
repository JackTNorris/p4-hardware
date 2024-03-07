import ipaddress
 
p4 = bfrt.cpu_test.pipe
 
def digest_collect(dev_id, pipe_id, directon, parser_id, session, msg):
    for digest in msg:
        print(digest);

p4.SwitchIngressDeparser.digest_a.callback_register(digest_collect)