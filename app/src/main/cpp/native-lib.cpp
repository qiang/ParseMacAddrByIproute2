#include <jni.h>
#include <string>
#include "ip.h"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_github_qiang_iproute2_parsemac_MainActivity_parseMac(JNIEnv *env, jobject thiz) {
    main();

    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}