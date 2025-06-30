#include "aws_iot_core.h"
#include "aws_iot_config.h"
#include "heartbeat.h"
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include "net_sample_common.h"

#if defined(CONFIG_MBEDTLS_MEMORY_DEBUG)
#include <mbedtls/memory_buffer_alloc.h>
#endif

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

static struct aws_iot_client aws_client;

int main(void)
{
	int ret;

	LOG_INF("AWS IoT Core MQTT Client starting...");

	/* Setup AWS IoT credentials */
	ret = aws_iot_setup_credentials();
	if (ret != 0) {
		LOG_ERR("Failed to setup credentials: %d", ret);
		return ret;
	}

	/* Wait for network connectivity */
	wait_for_network();

	/* Initialize AWS IoT client */
	ret = aws_iot_client_init(&aws_client);
	if (ret != 0) {
		LOG_ERR("Failed to initialize AWS IoT client: %d", ret);
		return ret;
	}

	/* Main application loop */
	for (;;) {
		/* Resolve broker address */
		ret = aws_iot_resolve_broker_addr(&aws_client);
		if (ret != 0) {
			LOG_ERR("Failed to resolve broker address: %d", ret);
			k_sleep(K_SECONDS(5));
			continue;
		}

		/* Connect to AWS IoT Core */
		ret = aws_iot_client_connect(&aws_client);
		if (ret != 0) {
			LOG_ERR("Failed to connect to AWS IoT Core: %d", ret);
			k_sleep(K_SECONDS(5));
			continue;
		}

		LOG_INF("=> Connected to AWS IoT Core successfully");

		/* Run the client loop */
		ret = aws_iot_client_loop(&aws_client);
		if (ret != 0) {
			LOG_ERR("AWS IoT client loop failed: %d", ret);
		}

		/* Disconnect and cleanup */
		aws_iot_client_disconnect(&aws_client);

		LOG_INF("=> Disconnected from AWS IoT Core");

#if defined(CONFIG_MBEDTLS_MEMORY_DEBUG)
		size_t cur_used, cur_blocks, max_used, max_blocks;

		mbedtls_memory_buffer_alloc_cur_get(&cur_used, &cur_blocks);
		mbedtls_memory_buffer_alloc_max_get(&max_used, &max_blocks);
		LOG_INF("mbedTLS heap usage: MAX %u/%u (%u) CUR %u (%u)", max_used,
			CONFIG_MBEDTLS_HEAP_SIZE, max_blocks, cur_used, cur_blocks);
#endif

		/* Wait before attempting to reconnect */
		k_sleep(K_SECONDS(1));
	}

	return 0;
}

// Start led blinking task
K_THREAD_DEFINE(heartbeat_id, HEARTBEAT_THREAD_STACKSIZE, heartbeat_task, NULL, NULL, NULL, 2, 0,
		0);
