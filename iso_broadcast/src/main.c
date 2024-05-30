#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/iso.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/random/rand32.h>
#include <zephyr/logging/log.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <zephyr/drivers/gpio.h>
#include "../../subsys/bluetooth/controller/include/ll.h"
#include "shared_stuff.h"
#include "shell.h"

LOG_MODULE_REGISTER(main, CONFIG_LOG_DEFAULT_LEVEL);

/* ---------------------------------------------------------------------------------------- */
/* General */
/* ---------------------------------------------------------------------------------------- */
#define TESLA_PAYLOAD_SIZE_BYTE                                                              \
	(2 * CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE) + CONFIG_PAYLOAD_SIZE_BYTE_KEY

#define BIS_ISO_CHAN_COUNT 2

#define ISO_TX_BUF_ENQUEUE_COUNT CONFIG_BT_ISO_TX_BUF_COUNT / BIS_ISO_CHAN_COUNT

#define PRINT_HEX(p_label, p_text, len)                                                      \
	({                                                                                       \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  	 \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          	 \
		LOG_INF("---- %s end  ----", p_label);                                             	 \
	})

#define SHA256_SIZE_BYTE 32
#define HMAC_SIZE_BYTE   32

#define CTRL_SUBEVENT_SIZE_BYTE_MAX 8 // based on v5.4

static uint8_t one_way_chain[CONFIG_ONE_WAY_CHAIN_LENGTH][SHA256_SIZE_BYTE];

/* Updated in background by controller */
extern uint8_t ctrl_subevent_payload[CTRL_SUBEVENT_SIZE_BYTE_MAX];

/* Used by controller in background */
uint8_t iso_rtn = CONFIG_RETRANSMISSIONS;

/* ---------------------------------------------------------------------------------------- */
/* LED */
/* ---------------------------------------------------------------------------------------- */
#define LED0_NODE DT_ALIAS(led0)
#define LED1_NODE DT_ALIAS(led1)

#if DT_NODE_HAS_STATUS(LED0_NODE, okay)
static const struct gpio_dt_spec led_gpio_0 = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
static const struct gpio_dt_spec led_gpio_1 = GPIO_DT_SPEC_GET(LED1_NODE, gpios);
#define HAS_LED 1
static void led(int led_num, int value)
{
	switch (led_num) {
	case 0:
		gpio_pin_set_dt(&led_gpio_0, value);
		break;
	case 1:
		gpio_pin_set_dt(&led_gpio_1, value);
		break;
	default:
		LOG_ERR("ERROR: no such LED");
		break;
	}
}
#endif

/* ---------------------------------------------------------------------------------------- */
/* Crypto */
/* ---------------------------------------------------------------------------------------- */
static int generate_seed(uint8_t *output, size_t output_size)
{
#ifndef CONFIG_RANDOM_SEED
	memset(output, 1, output_size);
	return 0;
#endif /* CONFIG_RANDOM_SEED */

	int err;
	err = sys_csrand_get(output, output_size);
	if (err) {
		LOG_ERR("sys_csrand_get failed! (Error: %d)", err);
		return -1;
	}
	return 0;
}

static int hash(const uint8_t *input, uint8_t *output, size_t length)
{
#if defined(HAS_LED)
	led(0, 255);
#endif /* HAS_LED */

	struct tc_sha256_state_struct sha_state;
	(void)tc_sha256_init(&sha_state);
	(void)tc_sha256_update(&sha_state, input, length);
	(void)tc_sha256_final(output, &sha_state);
#if defined(HAS_LED)
	led(0, 0);
#endif
	return 0;
}

static int generate_chain(uint8_t *seed, uint32_t len)
{
	int err;

	memcpy(&one_way_chain[0], seed, CONFIG_PAYLOAD_SIZE_BYTE_KEY);
	memset(&one_way_chain[0] + CONFIG_PAYLOAD_SIZE_BYTE_KEY, 0,
	       SHA256_SIZE_BYTE - CONFIG_PAYLOAD_SIZE_BYTE_KEY);

	for (int i = 0; i < len - 1; i++) {
		err = hash(one_way_chain[i], one_way_chain[i + 1], SHA256_SIZE_BYTE);
		if (err) {
			return -1;
		}
		memset(one_way_chain[i + 1] + CONFIG_PAYLOAD_SIZE_BYTE_KEY, 0,
		       SHA256_SIZE_BYTE - CONFIG_PAYLOAD_SIZE_BYTE_KEY);
	}

	return 0;
}

static int initOneWayChain()
{
	int err;
	uint8_t seed[SHA256_SIZE_BYTE] = {0};

	err = generate_seed(seed, CONFIG_PAYLOAD_SIZE_BYTE_KEY);
	if (err) {
		return -1;
	}

	err = generate_chain(seed, CONFIG_ONE_WAY_CHAIN_LENGTH);
	if (err) {
		return -1;
	}

	PRINT_HEX("L0", (char *)&one_way_chain[0], SHA256_SIZE_BYTE);
	PRINT_HEX("L1", (char *)&one_way_chain[1], SHA256_SIZE_BYTE);
	PRINT_HEX("L2", (char *)&one_way_chain[2], SHA256_SIZE_BYTE);
	PRINT_HEX("L3", (char *)&one_way_chain[3], SHA256_SIZE_BYTE);

	return 0;
}

static int generate_signature(uint8_t *message, uint8_t message_len, uint8_t *key,
			      uint8_t *signature)
{
	int err;

#if defined(HAS_LED)
	led(1, 255);
#endif /* HAS_LED */

	struct tc_hmac_state_struct h;

	err = tc_hmac_set_key(&h, key, SHA256_SIZE_BYTE);
	if (err == TC_CRYPTO_FAIL) {
		LOG_ERR("sys_csrand_get failed! (Error: %d)", err);
		return -1;
	}

	err = tc_hmac_init(&h);
	if (err == TC_CRYPTO_FAIL) {
		LOG_ERR("tc_hmac_init failed! (Error: %d)", err);
		return -1;
	}

	err = tc_hmac_update(&h, message, message_len);
	if (err == TC_CRYPTO_FAIL) {
		LOG_ERR("tc_hmac_update failed! (Error: %d)", err);
		return -1;
	}

	err = tc_hmac_final(signature, HMAC_SIZE_BYTE, &h);
	if (err == TC_CRYPTO_FAIL) {
		LOG_ERR("tc_hmac_final failed! (Error: %d)", err);
		return -1;
	}

#if defined(HAS_LED)
	led(1, 0);
#endif /* HAS_LED */
	// PRINT_HEX("SW SIG.:", (char*)signature, HMAC_SIZE_BYTE);
	return 0;
}

/* ---------------------------------------------------------------------------------------- */
/* ISO */
/* ---------------------------------------------------------------------------------------- */
#define BUF_ALLOC_TIMEOUT        (10)                /* milliseconds */
#define BIG_TERMINATE_TIMEOUT_US (60 * USEC_PER_SEC) /* microseconds */
#define BIG_SDU_INTERVAL_US      (10000)

NET_BUF_POOL_FIXED_DEFINE(bis_tx_pool, BIS_ISO_CHAN_COUNT,
			  BT_ISO_SDU_BUF_SIZE(CONFIG_BT_ISO_TX_MTU),
			  CONFIG_BT_CONN_TX_USER_DATA_SIZE, NULL);

static K_SEM_DEFINE(sem_big_cmplt, 0, BIS_ISO_CHAN_COUNT);
static K_SEM_DEFINE(sem_big_term, 0, BIS_ISO_CHAN_COUNT);

static uint8_t iso_data_payload[CONFIG_PAYLOAD_SIZE_BYTE_DATA] = {0};
static uint8_t iso_data_tesla[TESLA_PAYLOAD_SIZE_BYTE] = {0};

static uint32_t iso_send_count_payload = 0;
static uint16_t seq_num;

static struct bt_iso_big *big;
static struct bt_le_ext_adv *adv;

static void iso_connected(struct bt_iso_chan *chan)
{
	LOG_INF("ISO Channel %p connected", chan);

	seq_num = 0U;

	k_sem_give(&sem_big_cmplt);
}

static void iso_disconnected(struct bt_iso_chan *chan, uint8_t reason)
{
	LOG_INF("ISO Channel %p disconnected with reason 0x%02x", chan, reason);
	k_sem_give(&sem_big_term);
}

static void iso_sent_payload(struct bt_iso_chan *chan)
{
	int ret;
	struct net_buf *buf;

	if (seq_num >= CONFIG_ONE_WAY_CHAIN_LENGTH) {
		if (IS_ENABLED(CONFIG_SHELL_MODE)) {
			bt_iso_big_terminate(big);
		}
		return;
	}

	buf = net_buf_alloc(&bis_tx_pool, K_MSEC(BUF_ALLOC_TIMEOUT));
	if (!buf) {
		LOG_WRN("Data buffer allocate timeout on channel %p", chan);
		return;
	}

	net_buf_reserve(buf, BT_ISO_CHAN_SEND_RESERVE);
	sys_put_le32(iso_send_count_payload++, iso_data_payload);
	net_buf_add_mem(buf, iso_data_payload, CONFIG_PAYLOAD_SIZE_BYTE_DATA);
	ret = bt_iso_chan_send(chan, buf, seq_num++, BT_ISO_TIMESTAMP_NONE);
	if (ret < 0) {
		LOG_WRN("Unable to broadcast data on channel %p : %d", chan, ret);
		net_buf_unref(buf);
		return;
	}
}

static void iso_sent_tesla(struct bt_iso_chan *chan)
{
	int ret;
	struct net_buf *buf;

	if (seq_num >= CONFIG_ONE_WAY_CHAIN_LENGTH) {
		return;
	}

	buf = net_buf_alloc(&bis_tx_pool, K_MSEC(BUF_ALLOC_TIMEOUT));
	if (!buf) {
		LOG_WRN("Data buffer allocate timeout on channel %p", chan);
		return;
	}

	net_buf_reserve(buf, BT_ISO_CHAN_SEND_RESERVE);

	uint8_t *key_for_sig =
		one_way_chain[CONFIG_ONE_WAY_CHAIN_LENGTH - iso_send_count_payload - 1];
	uint8_t *key = one_way_chain[CONFIG_ONE_WAY_CHAIN_LENGTH - iso_send_count_payload];

	/* Signature Payload */
	uint8_t signature[HMAC_SIZE_BYTE];
	ret = generate_signature(iso_data_payload, CONFIG_PAYLOAD_SIZE_BYTE_DATA, key_for_sig,
				 signature);
	if (ret < 0) {
		LOG_WRN("Unable to generate a signature: %d", ret);
	}
	memcpy(iso_data_tesla, signature, CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE);

	/* Signature Control Subevent */
	ret = generate_signature(ctrl_subevent_payload, CTRL_SUBEVENT_SIZE_BYTE_MAX, key_for_sig,
				 signature);
	if (ret < 0) {
		LOG_WRN("Unable to generate a signature: %d", ret);
	}
	memcpy(iso_data_tesla + CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE, signature,
	       CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE);

	/* Key */
	memcpy(iso_data_tesla + (2 * CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE), key,
	       CONFIG_PAYLOAD_SIZE_BYTE_KEY);

	net_buf_add_mem(buf, iso_data_tesla, TESLA_PAYLOAD_SIZE_BYTE);

	ret = bt_iso_chan_send(chan, buf, seq_num, BT_ISO_TIMESTAMP_NONE);
	if (ret < 0) {
		LOG_WRN("Unable to broadcast data on channel %p : %d", chan, ret);
		net_buf_unref(buf);
		return;
	}

	if (seq_num >= CONFIG_ONE_WAY_CHAIN_LENGTH) {
		bt_iso_big_terminate(big);
	}

	LOG_INF("Sending payload: %u and 0x%x... on chan: %p", iso_send_count_payload,
		iso_data_tesla[0], chan);
}

static struct bt_iso_chan_ops iso_ops_payload = {
	.connected = iso_connected,
	.disconnected = iso_disconnected,
	.sent = iso_sent_payload,
};

static struct bt_iso_chan_ops iso_ops_tesla = {
	.connected = iso_connected,
	.disconnected = iso_disconnected,
	.sent = iso_sent_tesla,
};

static struct bt_iso_chan_io_qos iso_tx_qos_payload = {
	.sdu = CONFIG_PAYLOAD_SIZE_BYTE_DATA,
	.rtn = CONFIG_RETRANSMISSIONS,
	.phy = BT_GAP_LE_PHY_2M,
};

static struct bt_iso_chan_io_qos iso_tx_qos_tesla = {
	.sdu = TESLA_PAYLOAD_SIZE_BYTE,
	.rtn = 0,
	.phy = BT_GAP_LE_PHY_2M,
};

static struct bt_iso_chan_qos bis_iso_qos_payload = {
	.tx = &iso_tx_qos_payload,
};

static struct bt_iso_chan_qos bis_iso_qos_tesla = {
	.tx = &iso_tx_qos_tesla,
};

static struct bt_iso_chan bis_iso_chan[] = {
	{
		.ops = &iso_ops_payload,
		.qos = &bis_iso_qos_payload,
	},
	{
		.ops = &iso_ops_tesla,
		.qos = &bis_iso_qos_tesla,
	},
};

static struct bt_iso_chan *bis[] = {
	&bis_iso_chan[0],
	&bis_iso_chan[1],
};

static struct bt_iso_big_create_param big_create_param = {
	.num_bis = BIS_ISO_CHAN_COUNT,
	.bis_channels = bis,
	.interval = BIG_SDU_INTERVAL_US, /* in microseconds */
	.latency = 10,                   /* in milliseconds */
	.packing = 0,                    /* 0 - sequential, 1 - interleaved */
	.framing = 0,                    /* 0 - unframed, 1 - framed */
};

static int start_isochronous_transmission()
{
	int err;

	err = bt_iso_big_create(adv, &big_create_param, &big);
	if (err) {
		LOG_ERR("Failed to create BIG (err %d)", err);
		return 0;
	}

	for (uint8_t chan = 0U; chan < BIS_ISO_CHAN_COUNT; chan++) {
		LOG_INF("Waiting for BIG complete chan %u...", chan);
		err = k_sem_take(&sem_big_cmplt, K_FOREVER);
		if (err) {
			LOG_ERR("failed (err %d)", err);
			return 0;
		}
		LOG_INF("BIG create complete chan %u.", chan);
	}

	for (uint8_t i = 0; i < ISO_TX_BUF_ENQUEUE_COUNT; i++) {
		iso_sent_payload(&bis_iso_chan[0]);
		iso_sent_tesla(&bis_iso_chan[1]);
	}

	return 0;
}

/* ---------------------------------------------------------------------------------------- */
/* Main */
/* ---------------------------------------------------------------------------------------- */
int main(void)
{
	int err;

	LOG_INF("Starting ISO Broadcast Demo");

#if defined(HAS_LED)
	if (!gpio_is_ready_dt(&led_gpio_0) || !gpio_is_ready_dt(&led_gpio_1)) {
		LOG_WRN("LED gpio device not ready.");
		return 0;
	}

	err = gpio_pin_configure_dt(&led_gpio_0, GPIO_OUTPUT_INACTIVE);
	err |= gpio_pin_configure_dt(&led_gpio_1, GPIO_OUTPUT_INACTIVE);
	if (err) {
		return 0;
	}
#endif /* HAS_LED */

	if (IS_ENABLED(CONFIG_SHELL_MODE)) {
		err = init_shell();
	}
	// TODO: implement switch

	err = init_shared_stuff();
	if (err) {
		LOG_ERR("Shared stuff init failed (err %d)", err);
		return 0;
	}

	/* Initialize the one way Chain */
	err = initOneWayChain();
	if (err) {
		LOG_ERR("One way chain init failed (err %d)", err);
		return 0;
	}

	/* Initialize the Bluetooth Subsystem */
	err = bt_enable(NULL);
	if (err) {
		LOG_ERR("Bluetooth init failed (err %d)", err);
		return 0;
	}

	/* Create a non-connectable non-scannable advertising set */
	err = bt_le_ext_adv_create(BT_LE_EXT_ADV_NCONN_NAME, NULL, &adv);
	if (err) {
		LOG_ERR("Failed to create advertising set (err %d)", err);
		return 0;
	}

	/* Set periodic advertising parameters */
	err = bt_le_per_adv_set_param(adv, BT_LE_PER_ADV_DEFAULT);
	if (err) {
		LOG_ERR("Failed to set periodic advertising parameters"
			" (err %d)",
			err);
		return 0;
	}

	/* Enable Periodic Advertising */
	err = bt_le_per_adv_start(adv);
	if (err) {
		LOG_ERR("Failed to enable periodic advertising (err %d)", err);
		return 0;
	}

	/* Start extended advertising */
	err = bt_le_ext_adv_start(adv, BT_LE_EXT_ADV_START_DEFAULT);
	if (err) {
		LOG_ERR("Failed to start extended advertising (err %d)", err);
		return 0;
	}

	if (IS_ENABLED(CONFIG_SHELL_MODE)) {
		while (1) {
			k_sem_take(&start, K_FOREVER);
			iso_send_count_payload = 0;
			seq_num = 0U;
			(void)start_isochronous_transmission();
			k_sleep(K_MSEC(100));
		}
	}

	return start_isochronous_transmission();
}
