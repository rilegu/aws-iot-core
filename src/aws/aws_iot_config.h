#ifndef AWS_IOT_CONFIG_H
#define AWS_IOT_CONFIG_H

/* AWS IoT Core Configuration Constants */
#define SNTP_SERVER     "0.pool.ntp.org"
#define AWS_BROKER_PORT CONFIG_AWS_MQTT_PORT

/* Buffer sizes */
#define MQTT_BUFFER_SIZE 256u
#define APP_BUFFER_SIZE  4096u

/* Retry and backoff configuration */
#define MAX_RETRIES         10u
#define BACKOFF_EXP_BASE_MS 1000u
#define BACKOFF_EXP_MAX_MS  60000u
#define BACKOFF_CONST_MS    5000u

/* TLS certificate tags */
#define TLS_TAG_DEVICE_CERTIFICATE 1
#define TLS_TAG_DEVICE_PRIVATE_KEY 1
#define TLS_TAG_AWS_CA_CERTIFICATE 2

/* MQTT client configuration */
#define MQTT_CLIENT_NAME CONFIG_AWS_THING_NAME

/* ALPN protocol for port 443 */
#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
#define AWS_ALPN_PROTOCOL "x-amzn-mqtt-ca"
#endif

#endif /* AWS_IOT_CONFIG_H */
