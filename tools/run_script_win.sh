# 3.2 Build
# 3.2.1 Build Environment
python -m ectf_tools build.env --design ..\2023-ectf-UB-Cacti-design\ --name ub_test
# 3.2.2 Build Tools
python -m ectf_tools build.tools --design ..\2023-ectf-UB-Cacti-design\ --name ub_test
# 3.2.3 Build Deployment
python -m ectf_tools build.depl --design ..\2023-ectf-UB-Cacti-design\ --name ub_test --deployment ub_depl
# 3.2.4 Build Car and Paired Fob
python -m ectf_tools build.car_fob_pair  --design ..\2023-ectf-UB-Cacti-design --name ub_test --deployment ub_depl --car-out car_out --fob-out fob_out --car-name car_ub --fob-name fob_ub --car-id 1 --pair-pin 123456 --car-unlock-secret "Hello UB!" --car-feature1-secret "secret 1" --car-feature2-secret "secret 2" --car-feature3-secret "secret 3"

# 3.2.5 Build Unpaired Fob
python -m ectf_tools build.fob --design ..\2023-ectf-UB-Cacti-design\ --name ub_test --deployment ub_depl --fob-out fob_out --fob-name fob_ub

# 3.3 Load Device
# before loading the device, use uniflash to load bootloader to the board first
python -m ectf_tools device.load_hw --dev-in car_out --dev-name car_ub --dev-serial COM4

# 3.4 Start Bridge
python3 -m ectf_tools device.bridge --bridge-id 2233 --dev-serial COM3

# 3.5 Host Tools
# 3.5.1 pair fob
python -m ectf_tools run.pair --name ub_test --unpaired-fob-bridge 2233 --paired-fob-bridge 2233 --pair-pin 123456
# 3.5.2 Package Feature
python -m ectf_tools run.package --name ub_test --deployment ub_depl --package-out package_out --package-name package_ub --car-id 66 --feature-number 77
# 3.5.3 Enable Feature
python -m ectf_tools run.enable --name ub_test --fob-bridge 2233 --package-in package_out --package-name package_ub
# 3.5.4 Unlock Car
python -m ectf_tools run.unlock --name ub_test --car-bridge 2233