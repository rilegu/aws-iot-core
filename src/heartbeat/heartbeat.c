#include "heartbeat.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>

#define SLEEP_TIME_MS 1000
#define LED0_NODE     DT_ALIAS(led0)

void heartbeat_task(void)
{
	int ret;
	static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);

	if (!device_is_ready(led.port)) {
		return;
	}

	ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
	if (ret < 0) {
		return;
	}

	while (true) {
		gpio_pin_toggle_dt(&led);
		k_sleep(K_MSEC(SLEEP_TIME_MS));
	}
}
