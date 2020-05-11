#ifndef __LOG_H__
#define __LOG_H__

#define KLOG_ERROR(fmt, ...) printk("[%s:%d]Error: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define KLOG_WARN(fmt, ...) printk("[%s:%d]Warn: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define KLOG_DEBUG(fmt, ...) printk("[%s:%d]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define LOG_ERROR(fmt, ...) printf("[%s:%d]Error: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printf("[%s:%d]Warn: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printf("[%s:%d]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#endif