#include <jni.h>
#include <string>
#include<android/log.h>
#include "./system_properties/include/prop_area.h"

#define TAG    "Q_M" // 这个是自定义的LOG的标识
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG ,__VA_ARGS__) // 定义LOGD类型
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG ,__VA_ARGS__) // 定义LOGD类型

//https://cs.android.com/android/platform/superproject/+/master:system/core/init/property_service.cpp;l=90;bpv=1;bpt=1
extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_parsePropFile(JNIEnv *env, jobject thiz) {

    //cp /dev/__properties__/u:object_r:vendor_default_prop:s0 /data/local/tmp/my_prop
    const char *result;
    prop_area *area = prop_area::map_prop_area("/dev/__properties__/u:object_r:serialno_prop:s0");

    if (area->find("ro.vendor.serialno") != nullptr) {
        result = area->find("ro.vendor.serialno")->value;
        LOGD("内存读取 ro.vendor.serialno 为 ==> %s", result);
    } else {
        LOGE("文件中 ro.vendor.serialno 为空");
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_getPropByApi(JNIEnv *env, jobject thiz) {
    char temp[0x2800u];
    __system_property_get("ro.serialno", temp);  //获取不到
    LOGD("__system_property_get==>ro.serialno %s", temp);    //能够获取到

    char temp2[0x2800u];
    __system_property_get("ro.vendor.serialno", temp2);
    LOGD("__system_property_get==> ro.vendor.serialno %s", temp2);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_parsePropInMemroy(JNIEnv *env, jobject thiz) {

    char buf[256];
    FILE *fp;
    fp = fopen("/proc/self/maps", "r");
    LOGD("--------------开始遍历-------------------------");
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

//        if (strstr(buf, "/dev/__properties__/u:object_r:vendor_default_prop:s0") != nullptr) {
        if (strstr(buf, "/dev/__properties__/u:object_r") != nullptr) {
            //LOGD("内存读取 ==> %s", buf);
            LOGD("提取地址 ==> %lx--%lx %s", start, end, path);

            unsigned int size = end - start;

            const char *result;
            prop_area *area = prop_area::map_prop_mem(reinterpret_cast<void *>(start), size);

//            [persist.radio.serialno]: [ ]
//            [ro.boot.serialno]: [ ]
//            [ro.serialno]: [ ]
//            [vendor.boot.serialno]: [ ]

            if (area->find("ro.serialno") != nullptr) {
                result = area->find("ro.serialno")->value;
                LOGD("内存读取 ro.serialno 为 ==> %s", result);
            } else {
                LOGE("ro.serialno 为空");
            }

            if (area->find("ro.vendor.serialno") != nullptr) {
                result = area->find("ro.vendor.serialno")->value;
                LOGD("内存读取 ro.vendor.serialno 为 ==> %s", result);
            } else {
                LOGE("ro.vendor.serialno 为空");
            }
            if (area->find("ro.boot.serialno") != nullptr) {
                result = area->find("ro.boot.serialno")->value;
                LOGD("内存读取 ro.boot.serialno 为 ==> %s", result);
            } else {
                LOGE("ro.boot.serialno 为空");
            }

            if (area->find("vendor.boot.serialno") != nullptr) {
                result = area->find("vendor.boot.serialno")->value;
                LOGD("内存读取 vendor.boot.serialno 为 ==> %s", result);
            } else {
                LOGE("vendor.boot.serialno 为空");
            }

        }
    }
}extern "C"
JNIEXPORT void JNICALL
Java_com_github_propparser_MainActivity_mapPropInMemroy(JNIEnv *env, jobject thiz) {

    prop_area *pa;
    int s, fd;
    unsigned sz;
    char *prop_env;
    //获取环境变量ANDROID_PROPERTY_WORKSPACE
    //与上面init进程中设置对应
    prop_env = getenv("ANDROID_PROPERTY_WORKSPACE");
    //共享内存文件描述符 内存大小
    fd = atoi(prop_env);
    sz = atoi(prop_env + 1);
    //将文件描述符映射到当前进程虚拟空间内存，实现共享内存
    pa = static_cast<prop_area *>(mmap(0, sz, PROT_READ, MAP_SHARED, fd, 0));
    //全局变量指向共享系统属性内存首地址
    pa->find("ro.serialno");
}