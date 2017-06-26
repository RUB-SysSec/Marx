# Marx
Uncovering Class Hierarchies in C++ Programs

This repository holds the programs used for the NDSS 2017 paper [MARX: Uncovering Class Hierarchies in C++ Programs](https://www.syssec.rub.de/research/publications/marx/).


## Evaluation Data

The data used to evaluate Marx is available at [zenodo.org](https://zenodo.org/record/238686).


## Organization

Folder structure as follows:
- `include` contains the header files,
- `src` contains the source code itself,
- `patch` contains a patch to enable manual memory management for VEX,
- `ida_export` contains an IDA script creating a `.dmp` file,
- `scripts` contains helper scripts.


## Development Setup

Requires CMake, at least version 2.8. As for IDEs, QtCreator works pretty well
for C++ development and contains an useful debugger.

When using QtCreator, simply click on "Open Project" and select
`CMakeLists.txt`. It makes sense to let the build directory point to a
directory called `build` inside the project's root directory (in case your IDE
does not honor CMake's `RUNTIME_OUTPUT_DIRECTORY` variable).

Debug builds are considerably slower but are necessary for proper debugging
behavior. Make sure to set `CMAKE_BUILD_TYPE` accordingly in `CMakeLists.txt`
(you can do so from within QtCreator). In desperate cases, try the option "Run
CMake" from the context menu.

When developing from the command line, issue the following commands from the
project's root directory:
```
mkdir build && cd build
cmake ..
make -j{CPU_COUNT}
```

The project requires a patched version of _Valgrind_. To be more exact, only
the _VEX_ sub-project is actually used and patched.

Download Valgrind from [the official project page](http://valgrind.org/). We
recommend checking out the subversion repository. Revision 3203 of VEX is known
to work:
```
svn co svn://svn.valgrind.org/valgrind/trunk@15732 valgrind
cd valgrind/VEX/
svn update -r 3203
```

Configure the project as per its installation instructions. Switch to the `VEX`
directory and apply the patch found in folder `patch`:
```
cd VEX
patch -p0 < ../marx/patch/heap_allocation_patch.diff
```

First configure Valgrind by issuing `./autogen.sh` and `./configure`.
Then issue `make` and `make install` inside the `VEX` directory to install the
VEX components. The CMake project tries to include the library
`/usr/local/lib/valgrind/libvex-amd64-linux.a`. Make sure it exists.


## Usage

When developing on a new binary, the first step is to export data from an IDA
database. The IDAPython script found
in `ida_export` creates a dump file `{BINARY_NAME}.dmp` and exports all
necessary data used for the analysis in the folder the
binary lies in. Remember to set the pure_virtual_addr in the IDAPython script
before executing it. In case of Windows, the function is called `_purecall`.
In Linux, it is called `__cxa_pure_virtual`.

After exporting all data, a config file for Marx has to be created.
A config file looks like the following:
```
MODULENAME filezilla
TARGETDIR ../tests/filezilla/
FORMAT ELF64
NEWOPERATORS 2 431F80 432C00
EXTERNALMODULES 8 ../tests/libwx_gtk2u_aui/libwx_gtk2u_aui-3.1.so.0.0.0 ../tests/libwx_gtk2u_xrc/libwx_gtk2u_xrc-3.1.so.0.0.0 ../tests/libwx_gtk2u_adv/libwx_gtk2u_adv-3.1.so.0.0.0 ../tests/libwx_gtk2u_core/libwx_gtk2u_core-3.1.so.0.0.0 ../tests/libwx_baseu_net/libwx_baseu_net-3.1.so.0.0.0 ../tests/libwx_baseu/libwx_baseu-3.1.so.0.0.0 ../tests/libwx_gtk2u_html/libwx_gtk2u_html-3.1.so.0.0.0 ../tests/libwx_baseu_xml/libwx_baseu_xml-3.1.so.0.0.0
```

Further examples of config files can be seen in the `tests` directory.

When the config file is created, Marx can be executed by issuing the following command:
```
./marx ../tests/filezilla/config.cfg
```

Afterwards, the IDAPython script found in `ida_import` can be used to import the analyzed data back to IDA.

NOTE: Windows binaries have to be loaded at base address 0x0 (or rebased)
in IDA before exporting them. Also, the IDAPython script only supports Windows
binaries which are compiled with RTTI. Furthermore, specific functions
have to be blacklisted in Windows binaries
(because of compiler optimizations which would cause a lot of false-positives
during the analysis) that are in multiple vtables but do not belong together.
This is the case for example for short functions that do just zero a
register and do nothing more. See for further details the helper script
`ida_win_find_blacklist_functions.py`.