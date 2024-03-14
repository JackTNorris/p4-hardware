rm -rf $1.tofino
rm -rf $SDE_INSTALL/$1.tofino
rm -rf $SDE_INSTALL/share/p4/targets/tofino/$1.conf
bf-p4c $1.p4
sudo cp -r cpu_test.tofino $SDE_INSTALL
sudo cp cpu_test.tofino/cpu_test.conf $SDE_INSTALL/share/p4/targets/tofino