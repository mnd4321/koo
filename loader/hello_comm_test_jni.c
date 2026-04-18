#define _GNU_SOURCE
#include <errno.h>
#include <jni.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static const unsigned long kMagicKey = 0x53454c58UL;

JNIEXPORT jlong JNICALL
Java_com_aaa_rootdemo_MainActivity_nativeSendMembarrier(JNIEnv *env, jobject thiz,
							 jlong cmd, jlong token)
{
	long ret;
	(void)env;
	(void)thiz;

#if defined(__linux__)
#ifndef __NR_membarrier
#ifdef SYS_membarrier
#define __NR_membarrier SYS_membarrier
#endif
#endif
#ifndef __NR_membarrier
	return -1;
#endif
	errno = 0;
	ret = syscall(__NR_membarrier, kMagicKey, (unsigned long)cmd,
		      (unsigned long)token);
	return (jlong)ret;
#else
	return -1;
#endif
}

JNIEXPORT jstring JNICALL
Java_com_aaa_rootdemo_MainActivity_nativeLastErrnoString(JNIEnv *env, jobject thiz)
{
	(void)thiz;
	return (*env)->NewStringUTF(env, strerror(errno));
}
