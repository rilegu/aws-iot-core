#ifndef AWS_MQTT_H
#define AWS_MQTT_H

#include <stdint.h>
#include <stdbool.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include "aws_iot_config.h" // Include for MQTT_BUFFER_SIZE, MAX_RETRIES, etc.

/**
 * @brief MQTT event handler callback function type.
 * This function will be called by the aws_mqtt module when an MQTT event occurs.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @param evt Pointer to the MQTT event structure.
 */
typedef void (*aws_mqtt_event_handler_t)(struct mqtt_client *mqtt_client,
					 const struct mqtt_evt *evt);

/**
 * @brief Generic MQTT client context structure.
 * This structure holds all necessary information for an MQTT client.
 */
struct aws_mqtt_client {
	struct mqtt_client mqtt_client;      /**< Zephyr MQTT client instance. */
	struct sockaddr_in broker_addr;      /**< Broker address. */
	uint8_t rx_buffer[MQTT_BUFFER_SIZE]; /**< Receive buffer for MQTT messages. */
	uint8_t tx_buffer[MQTT_BUFFER_SIZE]; /**< Transmit buffer for MQTT messages. */
	bool connected;                      /**< Connection status. */
	aws_mqtt_event_handler_t event_cb;   /**< Callback for MQTT events. */
	void *user_data;                     /**< User-defined data passed to the event callback. */
};

/**
 * @brief Backoff context for connection retry logic.
 */
struct aws_mqtt_backoff_context {
	uint16_t retries_count; /**< Current retry attempt count. */
	uint16_t max_retries;   /**< Maximum number of retries. */
#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
	uint32_t attempt_max_backoff; /**< Maximum backoff for the current attempt (ms). */
	uint32_t max_backoff;         /**< Global maximum backoff (ms). */
#endif
};

/**
 * @brief Initialize the generic MQTT client.
 *
 * @param client Pointer to the aws_mqtt_client structure to initialize.
 * @param client_id MQTT client ID.
 * @param broker_port MQTT broker port.
 * @param endpoint MQTT broker endpoint hostname.
 * @param event_cb Callback function to handle MQTT events.
 * @param user_data User-defined data to be passed to the event callback.
 * @return 0 on success, negative error code on failure.
 */
int aws_mqtt_client_init(struct aws_mqtt_client *client, const char *client_id,
			 uint16_t broker_port, const char *endpoint,
			 aws_mqtt_event_handler_t event_cb, void *user_data);

/**
 * @brief Resolve the MQTT broker address.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @param endpoint The hostname of the MQTT broker.
 * @return 0 on success, negative error code on failure.
 */
int aws_mqtt_resolve_broker_addr(struct aws_mqtt_client *client, const char *endpoint);

/**
 * @brief Connect to the MQTT broker with retry logic.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_mqtt_client_connect(struct aws_mqtt_client *client);

/**
 * @brief Subscribe to an MQTT topic.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @param topic The topic string to subscribe to.
 * @param qos The desired QoS level for the subscription.
 * @return 0 on success, negative error code on failure.
 */
int aws_mqtt_subscribe_topic(struct aws_mqtt_client *client, const char *topic, enum mqtt_qos qos);

/**
 * @brief Publish a message to an MQTT topic.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @param topic Topic string.
 * @param payload Payload data.
 * @param payload_len Payload data length.
 * @param qos QoS level for the publish message.
 * @return 0 on success, negative error code on failure.
 */
int aws_mqtt_publish_message(struct aws_mqtt_client *client, const char *topic, uint8_t *payload,
			     size_t payload_len, enum mqtt_qos qos);

/**
 * @brief Main MQTT client loop. This function handles MQTT input/output and keepalives.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @return 0 on success, negative error code on failure (e.g., socket error, disconnect).
 */
int aws_mqtt_client_loop(struct aws_mqtt_client *client);

/**
 * @brief Disconnect from the MQTT broker.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @return 0 on success, negative error code on failure.
 */
int aws_mqtt_client_disconnect(struct aws_mqtt_client *client);

/**
 * @brief Check if the MQTT client is connected.
 *
 * @param client Pointer to the aws_mqtt_client structure.
 * @return true if connected, false otherwise.
 */
bool aws_mqtt_client_is_connected(struct aws_mqtt_client *client);

#endif /* AWS_MQTT_H */
