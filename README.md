### Wireshark-MQTT

MQTT dissector for Wireshark was developed for debugging
libemqtt (https://github.com/menudoproblema/libemqtt)

this fork add wireshark 1.12+ & lua 5.2 support on OS x(10.10).

Usage
=====

### install wireshark on os x with homebrew:
brew install wireshark --with-qt5

$ wireshark -X lua_script:mqtt.lua

If you want to install this as a plugin just copy the mqtt.lua to 
a wireshark plugin folder.
In windows this could be %APPDATA%\Wireshark\plugins


Others Setting same as originally library(https://github.com/menudoproblema/Wireshark-MQTT)
=======
