#include "aws_iot_core.h"
#include "aws_iot_config.h"
#include "creds/creds.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/data/json.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>

LOG_MODULE_REGISTER(aws_iot_core, LOG_LEVEL_DBG);

#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
static const char *const alpn_list[] = {AWS_ALPN_PROTOCOL};
#endif

static const sec_tag_t sec_tls_tags[] = {
	TLS_TAG_DEVICE_CERTIFICATE,
	TLS_TAG_AWS_CA_CERTIFICATE,
};

static const struct json_obj_descr json_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct aws_iot_publish_payload, counter, JSON_TOK_NUMBER),
};

static void aws_iot_mqtt_event_cb(struct mqtt_client *mqtt_client, const struct mqtt_evt *evt);
static void aws_iot_backoff_context_init(struct aws_iot_backoff_context *bo);
static void aws_iot_backoff_get_next(struct aws_iot_backoff_context *bo, uint32_t *next_backoff_ms);

const char *aws_iot_mqtt_evt_type_to_str(enum mqtt_evt_type type)
{
	static const char *const types[] = {
		"CONNACK", "DISCONNECT", "PUBLISH", "PUBACK",   "PUBREC",
		"PUBREL",  "PUBCOMP",    "SUBACK",  "UNSUBACK", "PINGRESP",
	};

	return (type < ARRAY_SIZE(types)) ? types[type] : "<unknown>";
}

int aws_iot_setup_credentials(void)
{
	int ret;

	ret = tls_credential_add(TLS_TAG_DEVICE_CERTIFICATE, TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 public_cert, public_cert_len);
	if (ret < 0) {
		LOG_ERR("Failed to add device certificate: %d", ret);
		goto exit;
	}

	ret = tls_credential_add(TLS_TAG_DEVICE_PRIVATE_KEY, TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, private_key_len);
	if (ret < 0) {
		LOG_ERR("Failed to add device private key: %d", ret);
		goto exit;
	}

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

	mqtt_client_init(&client->mqtt_client);

	client->mqtt_client.broker = &client->broker_addr;
	client->mqtt_client.evt_cb = aws_iot_mqtt_event_cb;

	client->mqtt_client.client_id.utf8 = (uint8_t *)MQTT_CLIENT_NAME;
	client->mqtt_client.client_id.size = strlen(MQTT_CLIENT_NAME);
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
	tls_config->hostname = CONFIG_AWS_ENDPOINT;
	tls_config->cert_nocopy = TLS_CERT_NOCOPY_NONE;

#if (CONFIG_AWS_MQTT_PORT == 443 && !defined(CONFIG_MQTT_LIB_WEBSOCKET))
	tls_config->alpn_protocol_name_list = alpn_list;
	tls_config->alpn_protocol_name_count = ARRAY_SIZE(alpn_list);
#endif

	client->messages_received_counter = 0;
	client->do_publish = false;
	client->do_subscribe = false;
	client->connected = false;

	return 0;
}

int aws_iot_resolve_broker_addr(struct aws_iot_client *client)
{
	if (!client) {
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

	sprintf(port_string, "%d", AWS_BROKER_PORT);
	ret = getaddrinfo(CONFIG_AWS_ENDPOINT, port_string, &hints, &ai);
	if (ret == 0) {
		char addr_str[INET_ADDRSTRLEN];

		memcpy(&client->broker_addr, ai->ai_addr,
		       MIN(ai->ai_addrlen, sizeof(struct sockaddr_storage)));

		inet_ntop(AF_INET, &client->broker_addr.sin_addr, addr_str, sizeof(addr_str));
		LOG_INF("Resolved: %s:%u", addr_str, htons(client->broker_addr.sin_port));
	} else {
		LOG_ERR("Failed to resolve hostname err = %d (errno = %d)", ret, errno);
	}

	freeaddrinfo(ai);

	return ret;
}

static void aws_iot_backoff_context_init(struct aws_iot_backoff_context *bo)
{
	__ASSERT_NO_MSG(bo != NULL);

	bo->retries_count = 0u;
	bo->max_retries = MAX_RETRIES;

#if defined(CONFIG_AWS_EXPONENTIAL_BACKOFF)
	bo->attempt_max_backoff = BACKOFF_EXP_BASE_MS;
	bo->max_backoff = BACKOFF_EXP_MAX_MS;
#endif
}

static void aws_iot_backoff_get_next(struct aws_iot_backoff_context *bo, uint32_t *next_backoff_ms)
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
	*next_backoff_ms = BACKOFF_CONST_MS;
	bo->retries_count++;
#endif
}

int aws_iot_client_connect(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	int ret;
	uint32_t backoff_ms;
	struct aws_iot_backoff_context bo;

	aws_iot_backoff_context_init(&bo);

	while (bo.retries_count <= bo.max_retries) {
		ret = mqtt_connect(&client->mqtt_client);
		if (ret == 0) {
			client->connected = true;
			goto exit;
		}

		aws_iot_backoff_get_next(&bo, &backoff_ms);

		LOG_ERR("Failed to connect: %d backoff delay: %u ms", ret, backoff_ms);
		k_msleep(backoff_ms);
	}

exit:
	return ret;
}

int aws_iot_subscribe_topic(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	int ret;
	struct mqtt_topic topics[] = {{
		.topic = {.utf8 = CONFIG_AWS_SUBSCRIBE_TOPIC,
			  .size = strlen(CONFIG_AWS_SUBSCRIBE_TOPIC)},
		.qos = CONFIG_AWS_QOS,
	}};
	const struct mqtt_subscription_list sub_list = {
		.list = topics,
		.list_count = ARRAY_SIZE(topics),
		.message_id = 1u,
	};

	LOG_INF("Subscribing to %hu topic(s)", sub_list.list_count);

	ret = mqtt_subscribe(&client->mqtt_client, &sub_list);
	if (ret != 0) {
		LOG_ERR("Failed to subscribe to topics: %d", ret);
	}

	return ret;
}

int aws_iot_publish_message(struct aws_iot_client *client, const char *topic, size_t topic_len,
			    uint8_t *payload, size_t payload_len)
{
	if (!client || !topic || !payload) {
		return -EINVAL;
	}

	static uint32_t message_id = 1u;

	int ret;
	struct mqtt_publish_param msg;

	msg.retain_flag = 0u;
	msg.dup_flag = 0u;
	msg.message.topic.topic.utf8 = topic;
	msg.message.topic.topic.size = topic_len;
	msg.message.topic.qos = CONFIG_AWS_QOS;
	msg.message.payload.data = payload;
	msg.message.payload.len = payload_len;
	msg.message_id = message_id++;

	ret = mqtt_publish(&client->mqtt_client, &msg);
	if (ret != 0) {
		LOG_ERR("Failed to publish message: %d", ret);
	}

	LOG_INF("PUBLISHED on topic \"%s\" [ id: %u qos: %u ], payload: %u B", topic,
		msg.message_id, msg.message.topic.qos, payload_len);
	LOG_HEXDUMP_DBG(payload, payload_len, "Published payload:");

	return ret;
}

int aws_iot_publish_counter(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	struct aws_iot_publish_payload pl = {.counter = client->messages_received_counter};

	json_obj_encode_buf(json_descr, ARRAY_SIZE(json_descr), &pl, client->app_buffer,
			    sizeof(client->app_buffer));

	return aws_iot_publish_message(client, CONFIG_AWS_PUBLISH_TOPIC,
				       strlen(CONFIG_AWS_PUBLISH_TOPIC), client->app_buffer,
				       strlen((char *)client->app_buffer));
}

ssize_t aws_iot_handle_received_message(struct aws_iot_client *client,
					const struct mqtt_publish_param *pub)
{
	if (!client || !pub) {
		return -EINVAL;
	}

	int ret;
	size_t received = 0u;
	const size_t message_size = pub->message.payload.len;
	const bool discarded = message_size > sizeof(client->app_buffer);

	LOG_INF("RECEIVED on topic \"%s\" [ id: %u qos: %u ] payload: %u / %u B",
		(const char *)pub->message.topic.topic.utf8, pub->message_id,
		pub->message.topic.qos, message_size, (uint32_t)sizeof(client->app_buffer));

	while (received < message_size) {
		uint8_t *p = discarded ? client->app_buffer : &client->app_buffer[received];

		ret = mqtt_read_publish_payload_blocking(&client->mqtt_client, p,
							 sizeof(client->app_buffer));
		if (ret < 0) {
			return ret;
		}

		received += ret;
	}

	if (!discarded) {
		LOG_HEXDUMP_DBG(client->app_buffer, MIN(message_size, 256u), "Received payload:");
	}

	/* Send ACK */
	switch (pub->message.topic.qos) {
	case MQTT_QOS_1_AT_LEAST_ONCE: {
		struct mqtt_puback_param puback;

		puback.message_id = pub->message_id;
		mqtt_publish_qos1_ack(&client->mqtt_client, &puback);
	} break;
	case MQTT_QOS_2_EXACTLY_ONCE: /* unhandled (not supported by AWS) */
	case MQTT_QOS_0_AT_MOST_ONCE: /* nothing to do */
	default:
		break;
	}

	return discarded ? -ENOMEM : received;
}

static void aws_iot_mqtt_event_cb(struct mqtt_client *mqtt_client, const struct mqtt_evt *evt)
{
	struct aws_iot_client *client =
		CONTAINER_OF(mqtt_client, struct aws_iot_client, mqtt_client);

	LOG_DBG("MQTT event: %s [%u] result: %d", aws_iot_mqtt_evt_type_to_str(evt->type),
		evt->type, evt->result);

	switch (evt->type) {
	case MQTT_EVT_CONNACK: {
		client->do_subscribe = true;
	} break;

	case MQTT_EVT_PUBLISH: {
		const struct mqtt_publish_param *pub = &evt->param.publish;

		aws_iot_handle_received_message(client, pub);
		client->messages_received_counter++;
#if !defined(CONFIG_AWS_TEST_SUITE_RECV_QOS1)
		client->do_publish = true;
#endif
	} break;

	case MQTT_EVT_SUBACK: {
#if !defined(CONFIG_AWS_TEST_SUITE_RECV_QOS1)
		client->do_publish = true;
#endif
	} break;

	case MQTT_EVT_DISCONNECT: {
		client->connected = false;
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

int aws_iot_client_loop(struct aws_iot_client *client)
{
	if (!client) {
		return -EINVAL;
	}

	int rc;
	int timeout;
	struct pollfd fds;

	if (!client->connected) {
		LOG_ERR("Client not connected");
		return -ENOTCONN;
	}

	fds.fd = client->mqtt_client.transport.tcp.sock;
	fds.events = POLLIN;

	for (;;) {
		timeout = mqtt_keepalive_time_left(&client->mqtt_client);
		rc = poll(&fds, 1u, timeout);
		if (rc >= 0) {
			if (fds.revents & POLLIN) {
				rc = mqtt_input(&client->mqtt_client);
				if (rc != 0) {
					LOG_ERR("Failed to read MQTT input: %d", rc);
					break;
				}
			}

			if (fds.revents & (POLLHUP | POLLERR)) {
				LOG_ERR("Socket closed/error");
				break;
			}

			rc = mqtt_live(&client->mqtt_client);
			if ((rc != 0) && (rc != -EAGAIN)) {
				LOG_ERR("Failed to live MQTT: %d", rc);
				break;
			}
		} else {
			LOG_ERR("poll failed: %d", rc);
			break;
		}

		if (client->do_publish) {
			client->do_publish = false;
			aws_iot_publish_counter(client);
		}

		if (client->do_subscribe) {
			client->do_subscribe = false;
			aws_iot_subscribe_topic(client);
		}
	}

	return rc;
}

int aws_iot_client_disconnect(struct aws_iot_client *client)
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

	return ret;
}

bool aws_iot_client_is_connected(struct aws_iot_client *client)
{
	return client ? client->connected : false;
}

uint32_t aws_iot_get_messages_received_count(struct aws_iot_client *client)
{
	return client ? client->messages_received_counter : 0;
}
