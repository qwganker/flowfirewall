#ifndef __LOG_H__
#define __LOG_H__

#define LOG_ERROR(fmt, ...) printk("[%s:%d]Error: " fmt "", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printk("[%s:%d]Warn: " fmt "", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printk("[%s:%d]: " fmt "", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#endif