#include "aws_iot_core.h"
#include "aws_iot_config.h"
#include "creds/creds.h" // Provides public_cert, private_key, ca_cert
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/mqtt.h> // Keep for mqtt_publish_param
#include <zephyr/net/tls_credentials.h>
#include <zephyr/data/json.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

LOG_MODULE_REGISTER(aws_iot_core, LOG_LEVEL_DBG);

// json_descr remains here as it's specific to aws_iot_publish_payload
static const struct json_obj_descr json_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct aws_iot_publish_payload, counter, JSON_TOK_NUMBER),
};

/**
 * @brief Handles received MQTT messages and processes them as AWS IoT application payloads.
 *
 * @param client Pointer to AWS IoT client structure.
 * @param pub MQTT publish parameters.
 * @return Number of bytes received, negative error code on failure.
 */
static ssize_t aws_iot_handle_received_message(struct aws_iot_client *client,
					       const struct mqtt_publish_param *pub)
{
	if (!client || !pub) {
		return -EINVAL;
	}

	int ret;
	size_t received = 0u;
	const size_t message_size = pub->message.payload.len;
	const bool discarded = message_size > sizeof(client->app_buffer);

	LOG_INF("=> RECEIVED on topic \"%s\" [ id: %u qos: %u ] payload: %u / %u B",
		(const char *)pub->message.topic.topic.utf8, pub->message_id,
		pub->message.topic.qos, message_size, (uint32_t)sizeof(client->app_buffer));

	while (received < message_size) {
		// Read payload from the MQTT client, store in app_buffer (or discard if msg is too
		// large)
		uint8_t *p = discarded ? client->app_buffer : &client->app_buffer[received];

		ret = mqtt_read_publish_payload_blocking(&client->mqtt.mqtt_client, p,
							 sizeof(client->app_buffer));
		if (ret < 0) {
			return ret;
		}

		received += ret;
	}

	if (!discarded) {
		LOG_HEXDUMP_DBG(client->app_buffer, MIN(message_size, 256u), "Received payload:");
	}

	/* Send ACK based on QoS */
	switch (pub->message.topic.qos) {
	case MQTT_QOS_1_AT_LEAST_ONCE: {
		struct mqtt_puback_param puback;

		puback.message_id = pub->message_id;
		mqtt_publish_qos1_ack(&client->mqtt.mqtt_client, &puback);
	} break;
	case MQTT_QOS_2_EXACTLY_ONCE: /* unhandled (not supported by AWS :( */
	case MQTT_QOS_0_AT_MOST_ONCE: /* nothing to do */
	default:
		break;
	}

	return discarded ? -ENOMEM : received;
}

/**
 * @brief Application-specific MQTT event handler.
 * This function is registered with the aws_mqtt module to handle events.
 *
 * @param mqtt_client Pointer to the Zephyr MQTT client instance.
 * @param evt Pointer to the MQTT event.
 */
static void aws_iot_mqtt_event_handler(struct mqtt_client *mqtt_client, const struct mqtt_evt *evt)
{
	struct aws_iot_client *client =
		CONTAINER_OF(mqtt_client, struct aws_iot_client, mqtt.mqtt_client);

	switch (evt->type) {
	case MQTT_EVT_CONNACK: {
		// Connection acknowledged, trigger subscription
		client->do_subscribe = true;
	} break;

	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *pub = &evt->param.publish;

		// Handle the received message and increment counter
		aws_iot_handle_received_message(client, pub);
		client->messages_received_counter++;
#if !defined(CONFIG_AWS_TEST_SUITE_RECV_QOS1)
		// Trigger a publish after receiving a message (if not testing QoS1 receive)
		client->do_publish = true;
#endif
	} break;

	case MQTT_EVT_SUBACK: {
#if !defined(CONFIG_AWS_TEST_SUITE_RECV_QOS1)
		// Subscription acknowledged, trigger initial publish
		client->do_publish = true;
#endif
	} break;

	case MQTT_EVT_DISCONNECT: {
		// Disconnected, client->mqtt.connected will be set to false by aws_mqtt
	} break;

	case MQTT_EVT_PUBACK:
	case MQTT_EVT_PUBREC:
	case MQTT_EVT_PUBREL:
	case MQTT_EVT_PUBCOMP:
	case MQTT_EVT_PINGRESP:
	case MQTT_EVT_UNSUBACK:
	default:
		break;
	}
}

int aws_iot_setup_credentials(void)
{
	int ret;

	// Add device certificate
	ret = tls_credential_add(TLS_TAG_DEVICE_CERTIFICATE, TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 public_cert, public_cert_len);
	if (ret < 0) {
		LOG_ERR("Failed to add device certificate: %d", ret);
		goto exit;
	}

	// Add device private key
	ret = tls_credential_add(TLS_TAG_DEVICE_PRIVATE_KEY, TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, private_key_len);
	if (ret < 0) {
		LOG_ERR("Failed to add device private key: %d", ret);
		goto exit;
	}

	// Add AWS CA certificate
	ret = tls_credential_add(TLS_TAG_AWS_CA_CERTIFICATE, TLS_CREDENTIAL_CA_CERTIFICATE, ca_cert,
				 ca_cert_len);
	if (ret < 0) {
		LOG_ERR("Failed to add CA certificate: %d", ret);
		goto exit;
	}

exit:
	return ret;
}

int aws_iot_client_init(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	memset(client, 0, sizeof(*client));

	// Initialize the embedded MQTT client using the common MQTT abstraction
	int ret = aws_mqtt_client_init(&client->mqtt, MQTT_CLIENT_NAME, AWS_BROKER_PORT,
				       CONFIG_AWS_ENDPOINT, aws_iot_mqtt_event_handler, client);
	if (ret != 0) {
		LOG_ERR("Failed to initialize MQTT client: %d", ret);
		return ret;
	}

	client->messages_received_counter = 0;
	client->do_publish = false;
	client->do_subscribe = false;

	return 0;
}

int aws_iot_resolve_broker_addr(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}
	// Use the MQTT abstraction to resolve the broker address
	return aws_mqtt_resolve_broker_addr(&client->mqtt, CONFIG_AWS_ENDPOINT);
}

int aws_iot_client_connect(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}
	// Use the MQTT abstraction to connect
	return aws_mqtt_client_connect(&client->mqtt);
}

int aws_iot_subscribe_topic(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}
	// Use the MQTT abstraction to subscribe
	client->do_subscribe = false; // Reset flag after attempting subscription
	return aws_mqtt_subscribe_topic(&client->mqtt, CONFIG_AWS_SUBSCRIBE_TOPIC, CONFIG_AWS_QOS);
}

int aws_iot_publish_counter(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	struct aws_iot_publish_payload pl = {.counter = client->messages_received_counter};
	size_t payload_len;

	// Encode payload to JSON
	int ret = json_obj_encode_buf(json_descr, ARRAY_SIZE(json_descr), &pl, client->app_buffer,
				      sizeof(client->app_buffer));
	if (ret < 0) {
		LOG_ERR("Failed to encode JSON payload: %d", ret);
		return ret;
	}
	payload_len = strlen((char *)client->app_buffer); // Assuming the JSON is null-terminated

	client->do_publish = false; // Reset flag after attempting publish

	// Use the MQTT abstraction to publish the message
	return aws_mqtt_publish_message(&client->mqtt, CONFIG_AWS_PUBLISH_TOPIC, client->app_buffer,
					payload_len, CONFIG_AWS_QOS);
}

int aws_iot_client_loop(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	// Application-specific logic before the MQTT loop
	if (client->do_publish) {
		aws_iot_publish_counter(client);
	}

	if (client->do_subscribe) {
		aws_iot_subscribe_topic(client);
	}

	// Run the generic MQTT client loop
	return aws_mqtt_client_loop(&client->mqtt);
}

int aws_iot_client_disconnect(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}
	// Use the MQTT abstraction to disconnect
	return aws_mqtt_client_disconnect(&client->mqtt);
}

bool aws_iot_client_is_connected(struct aws_iot_client *client)
{
	return client ? aws_mqtt_client_is_connected(&client->mqtt) : false;
}

uint32_t aws_iot_get_messages_received_count(struct aws_iot_client *client)
{
	return client ? client->messages_received_counter : 0;
}
