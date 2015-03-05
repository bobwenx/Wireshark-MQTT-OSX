Wireshark-MQTT
===========================

MQTT dissector for Wireshark was developed for debugging
libemqtt (https://github.com/menudoproblema/libemqtt)

This fork add wireshark 1.12+ & lua 5.2 support on OS x(10.10).

Usage
=====
* install wireshark(1.12) and lua(5.2) on os x(10.10+) via homebrew:
```
  brew install --build-from-source --with-qt5 wireshark lua
```
* copy [mqtt.lua](https://github.com/bobwenx/Wireshark-MQTT/blob/master/mqtt.lua) to ~/.wireshark/plugins/mqtt.lua
* using wireshark to capturing packets and filter MQTT by using keyword mqtt3
![Wireshark](wireshark-with-mqtt3.png)

Others Information 
=======
Same as originally library(https://github.com/menudoproblema/Wireshark-MQTT)
