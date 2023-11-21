# p4-hardware
Code I write for p4 switch hardware

## Compiling P4 Programs:
- bf-p4c <p4-program-name>.p4
- sudo cp -r [name].tofino $SDE_INSTALL/[name].tofino
- sudo cp [p4 program].tofino/[p4 program].conf $SDE_INSTALL/share/p4/targets/tofino/[p4 program].conf

## Running a P4 Program for CPU packet cloning
- cd $SDE 
- ./run_switchd.sh -p [p4 program]
- Run this shit:
```
ucli
pm
port-add 1/0 10G NONE
port-add 2/0 10G NONE
port-add 3/0 10G NONE
port-add 4/0 10G NONE
port-add 5/0 10G NONE
port-add 6/0 10G NONE
port-add 7/0 10G NONE
port-add 8/0 10G NONE
port-add 57/- 10G NONE
port-enb 1/0
port-enb 2/0
port-enb 3/0
port-enb 4/0
port-enb 5/0
port-enb 6/0
port-enb 7/0
port-enb 8/0
port-enb 57/-
exit
bfrt
bfrt
pre
port
add(DEV_PORT=192, COPY_TO_CPU_PORT_ENABLE=1)
..
..
pmu_data_recovery
pipe
MyIngress
ipv4_host
add_with_send(dst_addr='10.0.0.1', port=133)
add_with_send(dst_addr='10.0.0.2', port=132)
add_with_send(dst_addr='10.0.0.3', port=135)
add_with_send(dst_addr='10.0.0.5', port=141)
add_with_send(dst_addr='10.0.0.6', port=140)
add_with_send(dst_addr='10.0.0.7', port=143)
```
