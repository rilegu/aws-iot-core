#include "aws_mqtt.h"
#include "aws/aws_iot_config.h" // For MQTT_BUFFER_SIZE, etc.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

LOG_MODULE_REGISTER(aws_mqtt, LOG_LEVEL_DBG);

#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
static const char *const alpn_list[] = {AWS_ALPN_PROTOCOL};
#endif

// Define default sizes if not provided by config (for compilation outside Zephyr build system)
#ifndef CONFIG_MQTT_RX_BUF_SIZE
#define CONFIG_MQTT_RX_BUF_SIZE 256
#endif
#ifndef CONFIG_MQTT_TX_BUF_SIZE
#define CONFIG_MQTT_TX_BUF_SIZE 256
#endif

// TLS tags are specific to AWS IoT, but since the MQTT client handles TLS setup,
// they are defined here.
static const sec_tag_t sec_tls_tags[] = {
	TLS_TAG_DEVICE_CERTIFICATE,
	TLS_TAG_AWS_CA_CERTIFICATE,
};

/**
 * @brief Converts MQTT event type to a string for logging.
 *
 * @param type The MQTT event type.
 * @return String representation of the event type.
 */
static const char *aws_mqtt_evt_type_to_str(enum mqtt_evt_type type)
{
	static const char *const types[] = {
		"CONNACK", "DISCONNECT", "PUBLISH", "PUBACK",   "PUBREC",
		"PUBREL",  "PUBCOMP",    "SUBACK",  "UNSUBACK", "PINGRESP",
	};

	return (type < ARRAY_SIZE(types)) ? types[type] : "<unknown>";
}

/**
 * @brief Internal callback for MQTT events. It forwards the event to the user-defined callback.
 *
 * @param mqtt_client Pointer to the Zephyr MQTT client structure.
 * @param evt Pointer to the MQTT event.
 */
static void aws_mqtt_internal_event_cb(struct mqtt_client *mqtt_client, const struct mqtt_evt *evt)
{
	struct aws_mqtt_client *client =
		CONTAINER_OF(mqtt_client, struct aws_mqtt_client, mqtt_client);

	LOG_DBG("=> MQTT event: %s [%u] result: %d", aws_mqtt_evt_type_to_str(evt->type), evt->type,
		evt->result);

	if (client->event_cb) {
		client->event_cb(mqtt_client, evt);
	}

	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		client->connected = true;
		break;
	case MQTT_EVT_DISCONNECT:
		client->connected = false;
		break;
	default:
		break;
	}
}

/**
 * @brief Initializes the backoff context for connection retries.
 *
 * @param bo Pointer to the aws_mqtt_backoff_context structure.
 */
static void aws_mqtt_backoff_context_init(struct aws_mqtt_backoff_context *bo)
{
	__ASSERT_NO_MSG(bo != NULL);

	bo->retries_count = 0u;
	bo->max_retries = MAX_RETRIES; // From aws_iot_config.h

#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
	bo->attempt_max_backoff = BACKOFF_EXP_BASE_MS; // From aws_iot_config.h
	bo->max_backoff = BACKOFF_EXP_MAX_MS;          // From aws_iot_config.h
#endif
}

/**
 * @brief Calculates the next backoff delay for connection retries.
 *
 * @param bo Pointer to the aws_mqtt_backoff_context structure.
 * @param next_backoff_ms Pointer to store the calculated next backoff delay in milliseconds.
 */
static void aws_mqtt_backoff_get_next(struct aws_mqtt_backoff_context *bo,
				      uint32_t *next_backoff_ms)
{
	__ASSERT_NO_MSG(bo != NULL);
	__ASSERT_NO_MSG(next_backoff_ms != NULL);

#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
	if (bo->retries_count <= bo->max_retries) {
		*next_backoff_ms = sys_rand32_get() % (bo->attempt_max_backoff + 1u);

		/* Calculate max backoff for the next attempt (~ 2**attempt) */
		bo->attempt_max_backoff = MIN(bo->attempt_max_backoff * 2u, bo->max_backoff);
		bo->retries_count++;
	}
#else
	*next_backoff_ms = BACKOFF_CONST_MS; // From aws_iot_config.h
	bo->retries_count++;
#endif
}

int aws_mqtt_client_init(struct aws_mqtt_client *client, const char *client_id,
			 uint16_t broker_port, const char *endpoint,
			 aws_mqtt_event_handler_t event_cb, void *user_data)
{
	if (!client || !client_id || !endpoint) {
		return -EINVAL;
	}

	memset(client, 0, sizeof(*client));

	mqtt_client_init(&client->mqtt_client);

	client->mqtt_client.broker = &client->broker_addr;
	client->mqtt_client.evt_cb = aws_mqtt_internal_event_cb;
	client->event_cb = event_cb;
	client->user_data = user_data;

	client->mqtt_client.client_id.utf8 = (uint8_t *)client_id;
	client->mqtt_client.client_id.size = strlen(client_id);
	client->mqtt_client.password = NULL;
	client->mqtt_client.user_name = NULL;

	client->mqtt_client.keepalive = CONFIG_MQTT_KEEPALIVE;
	client->mqtt_client.protocol_version = MQTT_VERSION_3_1_1;

	client->mqtt_client.rx_buf = client->rx_buffer;
	client->mqtt_client.rx_buf_size = sizeof(client->rx_buffer);
	client->mqtt_client.tx_buf = client->tx_buffer;
	client->mqtt_client.tx_buf_size = sizeof(client->tx_buffer);

	/* Setup TLS */
	client->mqtt_client.transport.type = MQTT_TRANSPORT_SECURE;
	struct mqtt_sec_config *const tls_config = &client->mqtt_client.transport.tls.config;

	tls_config->peer_verify = TLS_PEER_VERIFY_REQUIRED;
	tls_config->cipher_list = NULL;
	tls_config->sec_tag_list = sec_tls_tags;
	tls_config->sec_tag_count = ARRAY_SIZE(sec_tls_tags);
	tls_config->hostname = endpoint;
	tls_config->cert_nocopy = TLS_CERT_NOCOPY_NONE;

#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
	tls_config->alpn_protocol_name_list = alpn_list;
	tls_config->alpn_protocol_name_count = ARRAY_SIZE(alpn_list);
#endif

	client->connected = false;

	return 0;
}

int aws_mqtt_resolve_broker_addr(struct aws_mqtt_client *client, const char *endpoint)
{
	if (!client || !endpoint) {
		return -EINVAL;
	}

	int ret;
	struct addrinfo *ai = NULL;

	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,
	};
	char port_string[6] = {0};

	sprintf(port_string, "%d", AWS_BROKER_PORT); // From aws_iot_config.h
	ret = getaddrinfo(endpoint, port_string, &hints, &ai);
	if (ret == 0) {
		char addr_str[INET_ADDRSTRLEN];

		memcpy(&client->broker_addr, ai->ai_addr,
		       MIN(ai->ai_addrlen, sizeof(struct sockaddr_storage)));

		inet_ntop(AF_INET, &client->broker_addr.sin_addr, addr_str, sizeof(addr_str));
		LOG_INF("=> Broker address resolved: %s:%u", addr_str,
			htons(client->broker_addr.sin_port));
	} else {
		LOG_ERR("Failed to resolve hostname err = %d (errno = %d)", ret, errno);
	}

	freeaddrinfo(ai);

	return ret;
}

int aws_mqtt_client_connect(struct aws_mqtt_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	int ret;
	uint32_t backoff_ms;
	struct aws_mqtt_backoff_context bo;

	aws_mqtt_backoff_context_init(&bo);

	while (bo.retries_count <= bo.max_retries) {
		ret = mqtt_connect(&client->mqtt_client);
		if (ret == 0) {
			LOG_INF("=> MQTT client connected.");
			client->connected = true;
			goto exit;
		}

		aws_mqtt_backoff_get_next(&bo, &backoff_ms);

		LOG_ERR("Failed to connect: %d backoff delay: %u ms", ret, backoff_ms);
		k_msleep(backoff_ms);
	}

exit:
	return ret;
}

int aws_mqtt_subscribe_topic(struct aws_mqtt_client *client, const char *topic, enum mqtt_qos qos)
{
	if (!client || !topic) {
		return -EINVAL;
	}

	int ret;
	struct mqtt_topic topics[] = {{
		.topic = {.utf8 = topic, .size = strlen(topic)},
		.qos = qos,
	}};
	const struct mqtt_subscription_list sub_list = {
		.list = topics,
		.list_count = ARRAY_SIZE(topics),
		.message_id = 1u,
	};

	LOG_INF("=> SUBSCRIBING to %hu topic(s): \"%s\" (QoS %d)", sub_list.list_count, topic, qos);

	ret = mqtt_subscribe(&client->mqtt_client, &sub_list);
	if (ret != 0) {
		LOG_ERR("Failed to subscribe to topic \"%s\": %d", topic, ret);
	}

	return ret;
}

int aws_mqtt_publish_message(struct aws_mqtt_client *client, const char *topic, uint8_t *payload,
			     size_t payload_len, enum mqtt_qos qos)
{
	if (!client || !topic || !payload) {
		return -EINVAL;
	}

	static uint32_t message_id = 1u; // Static to maintain across calls

	int ret;
	struct mqtt_publish_param msg;

	msg.retain_flag = 0u;
	msg.dup_flag = 0u;
	msg.message.topic.topic.utf8 = (uint8_t *)topic;
	msg.message.topic.topic.size = strlen(topic);
	msg.message.topic.qos = qos;
	msg.message.payload.data = payload;
	msg.message.payload.len = payload_len;
	msg.message_id = message_id++;

	ret = mqtt_publish(&client->mqtt_client, &msg);
	if (ret != 0) {
		LOG_ERR("Failed to publish message: %d", ret);
	}

	LOG_INF("=> PUBLISHED on topic \"%s\" [ id: %u qos: %u ], payload: %u B", topic,
		msg.message_id, msg.message.topic.qos, payload_len);
	LOG_HEXDUMP_DBG(payload, payload_len, "Published payload:");

	return ret;
}

int aws_mqtt_client_loop(struct aws_mqtt_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	int rc;
	int timeout;
	struct pollfd fds;

	if (!client->connected) {
		LOG_WRN("=> Client not connected, cannot run loop.");
		return -ENOTCONN;
	}

	// Setup pollfd for the MQTT client's socket
	fds.fd = client->mqtt_client.transport.tcp.sock;
	fds.events = POLLIN;

	// Loop indefinitely, handling MQTT communication
	for (;;) {
		// Calculate the time remaining until the next MQTT keep-alive
		timeout = mqtt_keepalive_time_left(&client->mqtt_client);
		if (timeout < 0) {
			LOG_ERR("Error getting keepalive time left: %d", timeout);
			return timeout;
		}

		// Wait for socket events or keep-alive timeout
		rc = poll(&fds, 1u, timeout);

		if (rc < 0) {
			LOG_ERR("poll failed: %d", rc);
			break; // Exit loop on poll error
		}

		if (rc > 0) { // Events occurred on the socket
			if (fds.revents & POLLIN) {
				// Data is available to read from the socket
				rc = mqtt_input(&client->mqtt_client);
				if (rc != 0) {
					LOG_ERR("Failed to read MQTT input: %d", rc);
					break; // Exit loop on input error
				}
			}

			if (fds.revents & (POLLHUP | POLLERR)) {
				// Socket was closed or an error occurred
				LOG_ERR("Socket closed/error");
				client->connected = false; // Update connection status
				break;                     // Exit loop
			}
		}

		// Process MQTT keep-alive and handle outgoing messages
		rc = mqtt_live(&client->mqtt_client);
		if ((rc != 0) && (rc != -EAGAIN)) {
			// -EAGAIN means no data was ready, which is fine
			LOG_ERR("Failed to keep MQTT alive: %d", rc);
			break; // Exit loop on live error
		}
	}

	return rc; // Return the last error code or 0 if loop exited cleanly
}

int aws_mqtt_client_disconnect(struct aws_mqtt_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	int ret = mqtt_disconnect(&client->mqtt_client, NULL);
	client->connected = false;

	if (client->mqtt_client.transport.tcp.sock >= 0) {
		close(client->mqtt_client.transport.tcp.sock);
		client->mqtt_client.transport.tcp.sock = -1;
	}

	LOG_INF("=> MQTT client disconnected.");

	return ret;
}

bool aws_mqtt_client_is_connected(struct aws_mqtt_client *client)
{
	return client ? client->connected : false;
}
