#ifndef AWS_IOT_CORE_H
#define AWS_IOT_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <zephyr/net/mqtt.h>   // Keep for mqtt_publish_param, etc.
#include <zephyr/net/socket.h> // Keep for sockaddr_in, etc.
#include "mqtt/aws_mqtt.h"     // Include the new MQTT abstraction header

/**
 * @brief AWS IoT Core client context structure.
 * Now embeds the generic MQTT client.
 */
struct aws_iot_client {
	struct aws_mqtt_client mqtt; /**< Embedded generic MQTT client. */
	uint8_t app_buffer[4096];    /**< Application buffer for receiving/publishing payloads. */
	uint32_t messages_received_counter; /**< Counter for received messages. */
	bool do_publish;                    /**< Flag to trigger publishing. */
	bool do_subscribe;                  /**< Flag to trigger subscription. */
};

/**
 * @brief Payload structure for publishing messages.
 */
struct aws_iot_publish_payload {
	uint32_t counter; /**< Counter value to be published. */
};

/**
 * @brief Setup TLS credentials for AWS IoT connection.
 *
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_setup_credentials(void);

/**
 * @brief Initialize AWS IoT Core client.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_client_init(struct aws_iot_client *client);

/**
 * @brief Resolve AWS IoT Core broker address.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_resolve_broker_addr(struct aws_iot_client *client);

/**
 * @brief Connect to AWS IoT Core with retry logic.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_client_connect(struct aws_iot_client *client);

/**
 * @brief Subscribe to configured AWS IoT topic.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_subscribe_topic(struct aws_iot_client *client);

/**
 * @brief Publish counter message using JSON format.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_publish_counter(struct aws_iot_client *client);

/**
 * @brief Main AWS IoT client loop.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_client_loop(struct aws_iot_client *client);

/**
 * @brief Disconnect from AWS IoT Core.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_iot_client_disconnect(struct aws_iot_client *client);

/**
 * @brief Check if client is connected.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return true if connected, false otherwise.
 */
bool aws_iot_client_is_connected(struct aws_iot_client *client);

/**
 * @brief Get received messages counter.
 *
 * @param client Pointer to AWS IoT client structure.
 * @return Number of messages received.
 */
uint32_t aws_iot_get_messages_received_count(struct aws_iot_client *client);

#endif /* AWS_IOT_CORE_H */
