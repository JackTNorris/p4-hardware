sudo rm -rf cpu_test.tofino
sudo rm -rf $SDE_INSTALL/cpu_test.tofino
sudo rm -rf $SDE_INSTALL/share/p4/targets/tofino/cpu_test.conf
bf-p4c cpu_test.p4
sudo cp -r cpu_test.tofino $SDE_INSTALL
sudo cp cpu_test.tofino/cpu_test.conf $SDE_INSTALL/share/p4/targets/tofino