#!/usr/bin/env python3
"""Wire keystore.properties into the Tauri-generated Android app module.

`tauri android init` regenerates gen/android on every CI run, so release
signing is patched in here instead of being committed. Idempotent.
"""
import sys

path = sys.argv[1]
src = open(path).read()
if "keystore.properties" in src:
    sys.exit(0)

# Newer Tauri templates already import java.util.Properties; a second import of the
# same name is a Kotlin error ("Conflicting import"). Add only what's missing.
header = "".join(f"{line}\n" for line in ("import java.io.FileInputStream", "import java.util.Properties") if line not in src)

signing = '''
    signingConfigs {
        create("release") {
            val props = Properties().apply { load(FileInputStream(rootProject.file("keystore.properties"))) }
            storeFile = file(props["storeFile"] as String)
            storePassword = props["storePassword"] as String
            keyAlias = props["keyAlias"] as String
            keyPassword = props["keyPassword"] as String
        }
    }
'''

src = header + src
src = src.replace("android {", "android {" + signing, 1)
marker = 'getByName("release") {'
if marker not in src:
    sys.exit("Could not find the release build type in " + path)
src = src.replace(marker, marker + '\n            signingConfig = signingConfigs.getByName("release")', 1)
open(path, "w").write(src)
print("Release signing configured.")
