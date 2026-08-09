# Builds steelospage, the one compiled piece of the SteelOS installer.
#
# Deliberately not using Calamares' own calamares_add_plugin() macro: that is
# written for modules built inside the Calamares source tree and pulls in its
# skip-list, translation and packaging machinery. A Calamares plugin is just a
# Qt plugin with a known IID, so out of tree it is an ordinary MODULE library
# plus a module.desc.

cmake_minimum_required(VERSION 3.16)
project(steelospage VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Qml Quick)
find_package(Calamares REQUIRED)

# The imported `calamares` target links the library but does not carry its
# include directory, and the headers land in <prefix>/include/libcalamares
# rather than somewhere the compiler looks by default. Find it by a header we
# actually include, so a layout change fails here with a clear message instead
# of at the first #include.
find_path(CALAMARES_INCLUDE_DIR
    NAMES DllMacro.h
    PATH_SUFFIXES libcalamares
    REQUIRED
)
message(STATUS "Calamares headers: ${CALAMARES_INCLUDE_DIR}")

add_library(steelospage MODULE SteelPageViewStep.cpp)

target_include_directories(steelospage PRIVATE ${CALAMARES_INCLUDE_DIR})

target_link_libraries(steelospage
    PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Qml
        Qt6::Quick
        calamares
)

# Calamares loads modules as libcalamares_viewmodule_<name>.so from its module
# directory, and finds them through module.desc's `load` key. The name here and
# the name there have to agree.
set_target_properties(steelospage PROPERTIES
    PREFIX ""
    OUTPUT_NAME "libcalamares_viewmodule_steelospage"
)

# PLUGINDLLEXPORT_PRO is what DllMacro.h keys the export attribute off for a
# plugin being built (as opposed to consumed).
target_compile_definitions(steelospage PRIVATE PLUGINDLLEXPORT_PRO)

include(GNUInstallDirs)
install(TARGETS steelospage
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/calamares/modules/steelospage)
install(FILES module.desc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/calamares/modules/steelospage)
