glib-compile-resources --target=icons_resource.c --generate-source icons.gresource.xml

g++ -g src/main.cpp src/utils.cpp src/tinyxml2.cpp icons_resource.c -o kaskad_users-configurator-gtk3 \
  -Iinclude $(pkg-config --cflags --libs gtkmm-3.0) -llber -lldap -lcrypto -std=c++17 -pthread -Wall -Wextra && ./kaskad_users-configurator-gtk3
