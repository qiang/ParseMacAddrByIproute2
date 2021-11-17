#include <jni.h>
#include <string>
#include "prop_area.h"
#include<android/log.h>

#define TAG    "Q_M" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型

//https://cs.android.com/android/platform/superproject/+/master:system/core/init/property_service.cpp;l=90;bpv=1;bpt=1
extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_parsePropFile(JNIEnv *env, jobject thiz) {

    //cp /dev/__properties__/u:object_r:vendor_default_prop:s0 /data/local/tmp/my_prop
    const char *result;
    prop_area *area = prop_area::map_prop_area("/data/local/tmp/my_prop");
    result = area->find("ro.vendor.serialno")->value;
    LOGD("文件内容为 ==> %s", result);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_getPropByApi(JNIEnv *env, jobject thiz) {
    char temp[0x2800u];
    __system_property_get("ro.serialno", temp);
    LOGD("__system_property_get==> %s", temp);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_parsePropInMemroy(JNIEnv *env, jobject thiz) {

    char buf[256];
    FILE *fp;
    fp = fopen("/proc/self/maps", "r");
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        unsigned long start, end;
        unsigned dev, sdev;
        unsigned long inode;
        unsigned long long offset;
        char prot[5];
        char path[64];

        //01a00000-01a20000 r--s 00000000 00:11 17341                              /dev/__properties__/u:object_r:vendor_default_prop:s0
        if (sscanf(buf, "%lx-%lx %s %llx %x:%x %lu %s", &start, &end, prot, &offset, &dev, &sdev,
                   &inode, path) != 8)
            continue;

        if (strstr(buf, "/dev/__properties__/u:object_r:vendor_default_prop:s0") != NULL) {
            LOGD("内存读取 ==> %s", buf);
            LOGD("提取地址 ==> %lx--%lx %s", start, end, path);

            unsigned int size = end - start;

            const char *result;
            prop_area *area = prop_area::map_prop_mem(reinterpret_cast<void *>(start), size);
            result = area->find("ro.vendor.serialno")->value;
            LOGD("内存读取serialno为 ==> %s", result);
        }

    }
}