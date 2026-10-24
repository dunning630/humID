# Tauri finds plugin commands, their argument classes and permission callbacks by reflection.
-keep class app.humid.docscan.** { *; }
# zxing-cpp's JNI side builds these by name.
-keep class zxingcpp.** { *; }
