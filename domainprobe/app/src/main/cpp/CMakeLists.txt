cmake_minimum_required(VERSION 3.22.1)
project(domainprobe C)
add_library(domainprobe SHARED probe.c)
target_link_libraries(domainprobe log)
target_compile_options(domainprobe PRIVATE -Wall -Wextra -Wno-unused-parameter)

# The same source as a standalone aarch64 executable, for the domains reached by
# pushing a binary rather than loading a library: u:r:shell:s0 (host runs it) and
# u:r:runas_app:s0 (run-as). Built with -DDOMAINPROBE_MAIN so probe.c compiles
# its main() instead of the JNI entry, and named lib*.so with no lib prefix
# stripped so the Android packager ships it in lib/<abi>/ where it can be pulled
# and exec'd. It links nothing Android-specific (LOGI becomes printf).
add_executable(domainprobe-cli probe.c)
target_compile_definitions(domainprobe-cli PRIVATE DOMAINPROBE_MAIN)
target_compile_options(domainprobe-cli PRIVATE -Wall -Wextra -Wno-unused-parameter)
set_target_properties(domainprobe-cli PROPERTIES OUTPUT_NAME "domainprobe-cli" PREFIX "lib" SUFFIX ".so")

# libmain.so: the framework loads this for an android:nativeService component and
# calls ANativeService_onCreate (see probe.c, DOMAINPROBE_NATIVESVC). Same probe,
# reached from the native/secondary zygote (zygote_next).
add_library(main SHARED probe.c)
target_compile_definitions(main PRIVATE DOMAINPROBE_NATIVESVC)
target_compile_options(main PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(main log dl)
