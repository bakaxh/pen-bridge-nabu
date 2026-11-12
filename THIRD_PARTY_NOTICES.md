# Third-party notices

Project source and scripts are available under the MIT license in `LICENSE`.
This does not replace the licenses of dependencies or external projects.

The prebuilt ARM64 executable was compiled with Zig 0.13.0 and statically
links musl and Zig compiler runtime code. Their notices accompany both the
repository and the installable ZIP:

- `LICENSES/Zig-MIT.txt`: Zig contributors' MIT license.
- `LICENSES/musl-COPYRIGHT.txt`: musl's complete copyright and license notice.
- `LICENSES/musl-SOURCE-NOTICES.txt`: supplementary source notices, including
  Arm, Sun Microsystems, BSD, and other permissive notices from the musl tree
  shipped with Zig 0.13.0. The collection deliberately includes notices for
  optional components that may not be linked into this executable.

No Xiaomi or Dell driver binary, firmware image, kernel dump, or proprietary
source is distributed here. Linux input/uinput definitions are used through
the toolchain's Linux UAPI headers.

The separately installed [XiaomiSmartPenPlus / 焦点笔 Plus](https://github.com/BaerYiTo/XiaomiSmartPenPlus)
provides the action configuration and execution interface. It is credited
for that functionality; its source, APK and branding assets are not bundled.
This bridge is an independent community adaptation, with no claim of
endorsement by Dell, Xiaomi, KernelSU, or XiaomiSmartPenPlus's author.
