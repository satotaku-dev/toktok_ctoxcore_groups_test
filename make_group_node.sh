g++ group_node_test.cpp -o group_node_test.exe \
-I/mingw64/include \
-I. \
-I"$HOME/libsodium_windows_x64/include" \
-I"$HOME/c-toxcore-ex" \
-L/mingw64/lib \
-L"$HOME/libsodium_windows_x64/lib" \
-L"$HOME/c-toxcore-ex/build_windows_x64" \
-ltoxcore \
-lsodium \
&& ./group_node_test.exe