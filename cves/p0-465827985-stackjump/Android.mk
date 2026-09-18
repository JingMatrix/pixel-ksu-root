LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
include $(BUILD_SYSTEM)/system_libs.mk
LOCAL_MODULE := repro
LOCAL_SRC_FILES := repro.cc incremental.cc clipboard.cc
#LOCAL_LDLIBS := -lEGL -lGLESv2
#LOCAL_SHARED_LIBRARIES := libbinder_ndk
LOCAL_LDLIBS := -lbinder_ndk -llog
LOCAL_CPPFLAGS := -std=c++20
include $(BUILD_EXECUTABLE)
