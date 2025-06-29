#ifndef AWS_IOT_CORE_H
#define AWS_IOT_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>

/**
 * @brief AWS IoT Core client context structure
 */
struct aws_iot_client {
	struct mqtt_client mqtt_client;
	struct sockaddr_in broker_addr;
	uint8_t rx_buffer[256];
	uint8_t tx_buffer[256];
	uint8_t app_buffer[4096];
	uint32_t messages_received_counter;
	bool do_publish;
	bool do_subscribe;
	bool connected;
};

/**
 * @brief Payload structure for publishing messages
 */
struct aws_iot_publish_payload {
	uint32_t counter;
};

/**
 * @brief Backoff context for connection retry logic
 */
struct aws_iot_backoff_context {
	uint16_t retries_count;
	uint16_t max_retries;
#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
	uint32_t attempt_max_backoff; /* ms */
	uint32_t max_backoff;         /* ms */
#endif
};

/**
 * @brief Initialize AWS IoT Core client
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_client_init(struct aws_iot_client *client);

/**
 * @brief Setup TLS credentials for AWS IoT connection
 *
 * @return 0 on success, negative error code on failure
 */
int aws_iot_setup_credentials(void);

/**
 * @brief Resolve AWS IoT Core broker address
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_resolve_broker_addr(struct aws_iot_client *client);

/**
 * @brief Connect to AWS IoT Core with retry logic
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_client_connect(struct aws_iot_client *client);

/**
 * @brief Subscribe to configured AWS IoT topic
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_subscribe_topic(struct aws_iot_client *client);

/**
 * @brief Publish message to AWS IoT Core
 *
 * @param client Pointer to AWS IoT client structure
 * @param topic Topic string
 * @param topic_len Topic string length
 * @param payload Payload data
 * @param payload_len Payload data length
 * @return 0 on success, negative error code on failure
 */
int aws_iot_publish_message(struct aws_iot_client *client, const char *topic, size_t topic_len,
			    uint8_t *payload, size_t payload_len);

/**
 * @brief Publish counter message using JSON format
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_publish_counter(struct aws_iot_client *client);

/**
 * @brief Handle received MQTT messages
 *
 * @param client Pointer to AWS IoT client structure
 * @param pub MQTT publish parameters
 * @return Number of bytes received, negative error code on failure
 */
ssize_t aws_iot_handle_received_message(struct aws_iot_client *client,
					const struct mqtt_publish_param *pub);

/**
 * @brief Main AWS IoT client loop
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_client_loop(struct aws_iot_client *client);

/**
 * @brief Disconnect from AWS IoT Core
 *
 * @param client Pointer to AWS IoT client structure
 * @return 0 on success, negative error code on failure
 */
int aws_iot_client_disconnect(struct aws_iot_client *client);

/**
 * @brief Check if client is connected
 *
 * @param client Pointer to AWS IoT client structure
 * @return true if connected, false otherwise
 */
bool aws_iot_client_is_connected(struct aws_iot_client *client);

/**
 * @brief Get received messages counter
 *
 * @param client Pointer to AWS IoT client structure
 * @return Number of messages received
 */
uint32_t aws_iot_get_messages_received_count(struct aws_iot_client *client);

#endif /* AWS_IOT_CORE_H */
