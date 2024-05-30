#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/iso.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include "lc3.h"

/* ---------------------------------------------------------------------------------------- */
/* Settings */
/* ---------------------------------------------------------------------------------------- */

#define BIG_SDU_INTERVAL_US 10000
#define BIS_TIMOUT_MS       100

/* ---------------------------------------------------------------------------------------- */
/* General */
/* ---------------------------------------------------------------------------------------- */
#define RENDERING_FIFO_SIZE 10
#define RENDERING_START     3 // start when 3 packets are in FIFO == 3 packets in FIFO at all times

#define BIS_ISO_CHAN_COUNT 2

#define PRINT_HEX(p_label, p_text, len)                                                      \
	({                                                                                       \
		LOG_INF("---- %s (len: %u): ----", p_label, len);                                  	 \
		LOG_HEXDUMP_INF(p_text, len, "Content:");                                          	 \
		LOG_INF("---- %s end  ----", p_label);                                             	 \
	})
LOG_MODULE_REGISTER(sha256, LOG_LEVEL_DBG);

#define CTRL_SUBEVENT_SIZE_BYTE_MAX 8 // based on v5.4
#define SHA256_SIZE_BYTE            32
#define HMAC_SIZE_BYTE              32

/* Updated in background by controller */
extern uint8_t ctrl_subevent_key[SHA256_SIZE_BYTE];
extern uint8_t ctrl_subevent_signature[HMAC_SIZE_BYTE];

static lc3_decoder_t lc3_decoder;
static lc3_decoder_mem_48k_t lc3_decoder_mem;

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
		printk("ERROR: no such LED\n");
		break;
	}
}
#endif

/* ---------------------------------------------------------------------------------------- */
/* ISO */
/* ---------------------------------------------------------------------------------------- */
#define TIMEOUT_SYNC_CREATE K_SECONDS(10)
#define NAME_LEN            30

#define BT_LE_SCAN_CUSTOM                                                                    \
	BT_LE_SCAN_PARAM(BT_LE_SCAN_TYPE_ACTIVE, BT_LE_SCAN_OPT_NONE, BT_GAP_SCAN_FAST_INTERVAL, \
			 BT_GAP_SCAN_FAST_WINDOW)

#define PA_RETRY_COUNT 6

static bool per_adv_found;
static bool per_adv_lost;
static bt_addr_le_t per_addr;
static uint8_t per_sid;
static uint32_t per_interval_us;

static K_SEM_DEFINE(sem_per_adv, 0, 1);
static K_SEM_DEFINE(sem_per_sync, 0, 1);
static K_SEM_DEFINE(sem_per_sync_lost, 0, 1);
static K_SEM_DEFINE(sem_per_big_info, 0, 1);
static K_SEM_DEFINE(sem_big_sync, 0, BIS_ISO_CHAN_COUNT);
static K_SEM_DEFINE(sem_big_sync_lost, 0, BIS_ISO_CHAN_COUNT);

/* ---------------------------------------------------------------------------------------- */
/* Crypto */
/* ---------------------------------------------------------------------------------------- */
static int hash(const uint8_t *input, uint8_t *output, size_t length)
{
#if defined(HAS_LED)
	led(0, 255);
#endif
	struct tc_sha256_state_struct sha_state;
	(void)tc_sha256_init(&sha_state);
	(void)tc_sha256_update(&sha_state, input, length);
	(void)tc_sha256_final(output, &sha_state);
#if defined(HAS_LED)
	led(0, 0);
#endif
	return 0;
}

int generate_signature(uint8_t *message, uint8_t message_len, uint8_t *key, uint8_t *signature)
{
	int err;

#if defined(HAS_LED)
	led(1, 255);
#endif

	struct tc_hmac_state_struct h;

	err = tc_hmac_set_key(&h, key, SHA256_SIZE_BYTE);
	if (err == TC_CRYPTO_FAIL) {
		printk("sys_csrand_get failed! (Error: %d)\n", err);
		return -1;
	}

	err = tc_hmac_init(&h);
	if (err == TC_CRYPTO_FAIL) {
		printk("tc_hmac_init failed! (Error: %d)\n", err);
		return -1;
	}

	err = tc_hmac_update(&h, message, message_len);
	if (err == TC_CRYPTO_FAIL) {
		printk("tc_hmac_update failed! (Error: %d)\n", err);
		return -1;
	}

	err = tc_hmac_final(signature, HMAC_SIZE_BYTE, &h);
	if (err == TC_CRYPTO_FAIL) {
		printk("tc_hmac_final failed! (Error: %d)\n", err);
		return -1;
	}

#if defined(HAS_LED)
	led(1, 0);
#endif
	// PRINT_HEX("SW SIG.:", (char*)signature, HMAC_SIZE_BYTE);
	return 0;
}

/* ---------------------------------------------------------------------------------------- */
/* ISO */
/* ---------------------------------------------------------------------------------------- */
static void scan_recv(const struct bt_le_scan_recv_info *info, struct net_buf_simple *buf)
{
	if (!per_adv_found && info->interval) {
		per_adv_found = true;

		per_sid = info->sid;
		per_interval_us = BT_CONN_INTERVAL_TO_US(info->interval);
		bt_addr_le_copy(&per_addr, info->addr);

		k_sem_give(&sem_per_adv);
	}
}

static struct bt_le_scan_cb scan_callbacks = {
	.recv = scan_recv,
};

static void sync_cb(struct bt_le_per_adv_sync *sync, struct bt_le_per_adv_sync_synced_info *info)
{
	k_sem_give(&sem_per_sync);
}

static void term_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_term_info *info)
{
	char le_addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));

	printk("PER_ADV_SYNC[%u]: [DEVICE]: %s sync terminated\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr);

	per_adv_lost = true;
	k_sem_give(&sem_per_sync_lost);
}

static void recv_cb(struct bt_le_per_adv_sync *sync,
		    const struct bt_le_per_adv_sync_recv_info *info, struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char data_str[129];

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));
	bin2hex(buf->data, buf->len, data_str, sizeof(data_str));

	printk("PER_ADV_SYNC[%u]: [DEVICE]: %s, tx_power %i, "
	       "RSSI %i, CTE %u, data length %u, data: %s\n",
	       bt_le_per_adv_sync_get_index(sync), le_addr, info->tx_power, info->rssi,
	       info->cte_type, buf->len, data_str);
}

static void biginfo_cb(struct bt_le_per_adv_sync *sync, const struct bt_iso_biginfo *biginfo)
{
	k_sem_give(&sem_per_big_info);
}

static struct bt_le_per_adv_sync_cb sync_callbacks = {
	.synced = sync_cb,
	.term = term_cb,
	.recv = recv_cb,
	.biginfo = biginfo_cb,
};

struct iso_packet {
	uint8_t payload[CONFIG_PAYLOAD_SIZE_BYTE_DATA];
	uint8_t signature_payload[CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE];
	uint8_t signature_ctrl[CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE];
	uint8_t key[CONFIG_PAYLOAD_SIZE_BYTE_KEY];
	uint8_t key_valid;
	uint8_t lost;
};

static struct iso_packet fifo[RENDERING_FIFO_SIZE];
static uint8_t prod_blk_idx = 0;
static uint8_t cons_blk_idx = 0;
#define NEXT_IDX(i) (((i) < (RENDERING_FIFO_SIZE - 1)) ? ((i) + 1) : 0)
#define PREV_IDX(i) (((i) > 0) ? ((i) - 1) : (RENDERING_FIFO_SIZE - 1))
#define PEAK_IDX(i) ((i) % RENDERING_FIFO_SIZE)

void my_work_handler(struct k_work *work)
{
	struct iso_packet *packet, *packet_future;
	uint32_t next_out_blk_idx = NEXT_IDX(cons_blk_idx);
	packet = (struct iso_packet *)&fifo[cons_blk_idx];
	packet_future = (struct iso_packet *)&fifo[next_out_blk_idx];

	if (lc3_decoder == NULL) {
		printk("LC3 decoder not setup, cannot decode data.\n");
		return;
	}

	/* Restore lost key(s) from received future events */
	uint8_t padded_key[SHA256_SIZE_BYTE] = {0};
	uint8_t hashed_key[SHA256_SIZE_BYTE];
	struct iso_packet *p_i, *p_ii;

	for (int8_t i = RENDERING_START - 2; i >= 0; i--) {
		p_i = (struct iso_packet *)&fifo[PEAK_IDX(cons_blk_idx + i)];
		p_ii = (struct iso_packet *)&fifo[PEAK_IDX(cons_blk_idx + i + 1)];

		if (p_ii->key_valid && !p_i->key_valid) {
			memcpy(padded_key, p_ii->key, CONFIG_PAYLOAD_SIZE_BYTE_KEY);
			(void)hash(padded_key, hashed_key, SHA256_SIZE_BYTE);
			memcpy(p_i->key, hashed_key, CONFIG_PAYLOAD_SIZE_BYTE_KEY);
			p_i->key_valid = 1;
		}
	}

	/* Print FIFO */
	char fifostr[RENDERING_START + 1] = {'\0'};
	for (uint8_t i = 0; i < RENDERING_START; i++) {
		fifostr[i] = '0';
		if (fifo[PEAK_IDX(cons_blk_idx + i)].key_valid) {
			fifostr[i] = '1';
		}
	}
	printk("[%s] ", fifostr);

	/* Exit if current data packet is lost */
	if (packet->lost) {
		printk("LOST\n");
		cons_blk_idx = next_out_blk_idx;
		return;
	}

	printk("Pay: %u ", sys_get_le32(packet->payload));

#if defined(HAS_LED)
	led(0, 255);
#endif

	uint8_t key_valid = false;
	uint8_t packet_valid = false;

	/* Validate authenticity of future key */
	memcpy(padded_key, packet_future->key, CONFIG_PAYLOAD_SIZE_BYTE_KEY);
	(void)hash(padded_key, hashed_key, SHA256_SIZE_BYTE);
	if (memcmp(hashed_key, packet->key, CONFIG_PAYLOAD_SIZE_BYTE_KEY) == 0) {
		printk("Key 1 ");
		key_valid = 1;
	} else {
		printk("Key 0 ");
	}

	/* Validate current signature with future key */
	uint8_t signature_calc[HMAC_SIZE_BYTE];
	generate_signature(packet->payload, CONFIG_PAYLOAD_SIZE_BYTE_DATA, padded_key,
			   signature_calc);
	if (memcmp(packet->signature_payload, signature_calc, CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE) ==
	    0) {
		printk("Signature(s) 1\n");
		packet_valid = 1;
	} else {
		printk("Signature(s) 0\n");
	}

#if defined(HAS_LED)
	led(0, 0);
#endif

#if defined(HAS_LED)
	led(1, 255);
#endif

#if defined(HAS_LED)
	led(1, 0);
#endif

	cons_blk_idx = next_out_blk_idx;
}
K_WORK_DEFINE(my_work, my_work_handler);

static void iso_recv_payload(struct bt_iso_chan *chan, const struct bt_iso_recv_info *info,
			     struct net_buf *buf)
{
	printk("%u |", RENDERING_START);
	if (!buf->len) {
		printk(" 0");
		fifo[prod_blk_idx].lost = 1;
		return;
	}
	printk(" 1");

	memcpy(&fifo[prod_blk_idx].payload, buf->data, CONFIG_PAYLOAD_SIZE_BYTE_DATA);
	fifo[prod_blk_idx].lost = 0;
}

static void iso_recv_tesla(struct bt_iso_chan *chan, const struct bt_iso_recv_info *info,
			   struct net_buf *buf)
{
	if (!buf->len) {
		printk(" 0 | ");
		fifo[prod_blk_idx].key_valid = 0;
	} else {
		printk(" 1 | ");
		uint8_t *signature_payload = buf->data;
		uint8_t *signature_ctrl = signature_payload + CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE;
		uint8_t *key = signature_ctrl + CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE;

		memcpy(&fifo[prod_blk_idx].signature_payload, signature_payload,
		       CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE);
		memcpy(&fifo[prod_blk_idx].signature_ctrl, signature_ctrl,
		       CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE);
		memcpy(&fifo[prod_blk_idx].key, key, CONFIG_PAYLOAD_SIZE_BYTE_KEY);

		fifo[prod_blk_idx].key_valid = 1;

		memcpy(ctrl_subevent_key, key, CONFIG_PAYLOAD_SIZE_BYTE_KEY);
		memcpy(ctrl_subevent_signature, signature_ctrl, CONFIG_PAYLOAD_SIZE_BYTE_SIGNATURE);
	}

	prod_blk_idx = NEXT_IDX(prod_blk_idx);

	if (info->seq_num >= RENDERING_START - 1) {
		k_work_submit(&my_work);
	} else {
		printk("\n");
	}
}

static void iso_connected(struct bt_iso_chan *chan)
{
	printk("ISO Channel %p connected\n", chan);
	k_sem_give(&sem_big_sync);
}

static void iso_disconnected(struct bt_iso_chan *chan, uint8_t reason)
{
	printk("ISO Channel %p disconnected with reason 0x%02x\n", chan, reason);

	if (reason != BT_HCI_ERR_OP_CANCELLED_BY_HOST) {
		k_sem_give(&sem_big_sync_lost);
	}
}

static struct bt_iso_chan_ops iso_ops_payload = {
	.recv = iso_recv_payload,
	.connected = iso_connected,
	.disconnected = iso_disconnected,
};

static struct bt_iso_chan_ops iso_ops_tesla = {
	.recv = iso_recv_tesla,
	.connected = iso_connected,
	.disconnected = iso_disconnected,
};

static struct bt_iso_chan_io_qos iso_rx_qos[BIS_ISO_CHAN_COUNT];

static struct bt_iso_chan_qos bis_iso_qos[] = {
	{
		.rx = &iso_rx_qos[0],
	},
	{
		.rx = &iso_rx_qos[1],
	},
};

static struct bt_iso_chan bis_iso_chan[] = {
	{
		.ops = &iso_ops_payload,
		.qos = &bis_iso_qos[0],
	},
	{
		.ops = &iso_ops_tesla,
		.qos = &bis_iso_qos[1],
	},
};

static struct bt_iso_chan *bis[] = {
	&bis_iso_chan[0],
	&bis_iso_chan[1],
};

static struct bt_iso_big_sync_param big_sync_param = {
	.bis_channels = bis,
	.num_bis = BIS_ISO_CHAN_COUNT,
	.bis_bitfield = (BIT_MASK(BIS_ISO_CHAN_COUNT) << 1),
	.mse = 1,
	.sync_timeout = BIS_TIMOUT_MS, /* in 10 ms units */
};

int main(void)
{
	struct bt_le_per_adv_sync_param sync_create_param;
	struct bt_le_per_adv_sync *sync;
	struct bt_iso_big *big;
	uint32_t sem_timeout_us;
	int err;

	printk("Starting Synchronized Receiver Demo\n");

#if defined(HAS_LED)
	if (!gpio_is_ready_dt(&led_gpio_0) || !gpio_is_ready_dt(&led_gpio_1)) {
		printk("LED gpio device not ready.\n");
		return 0;
	}

	err = gpio_pin_configure_dt(&led_gpio_0, GPIO_OUTPUT_INACTIVE);
	err |= gpio_pin_configure_dt(&led_gpio_1, GPIO_OUTPUT_INACTIVE);
	if (err) {
		return 0;
	}
#endif /* HAS_LED */

	lc3_decoder = lc3_setup_decoder(10000, 24000, 0, &lc3_decoder_mem);
	if (lc3_decoder == NULL) {
		printk("ERROR: Failed to setup LC3 encoder - wrong parameters?\n");
	}

	/* Initialize the Bluetooth Subsystem */
	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}

	printk("Scan callbacks register...");
	bt_le_scan_cb_register(&scan_callbacks);
	printk("success.\n");

	printk("Periodic Advertising callbacks register...");
	bt_le_per_adv_sync_cb_register(&sync_callbacks);
	printk("Success.\n");

	do {
		per_adv_lost = false;

		printk("Start scanning...");
		err = bt_le_scan_start(BT_LE_SCAN_CUSTOM, NULL);
		if (err) {
			printk("failed (err %d)\n", err);
			return 0;
		}
		printk("success.\n");

		printk("Waiting for periodic advertising...\n");
		per_adv_found = false;
		err = k_sem_take(&sem_per_adv, K_FOREVER);
		if (err) {
			printk("failed (err %d)\n", err);
			return 0;
		}
		printk("Found periodic advertising.\n");

		printk("Stop scanning...");
		err = bt_le_scan_stop();
		if (err) {
			printk("failed (err %d)\n", err);
			return 0;
		}
		printk("success.\n");

		printk("Creating Periodic Advertising Sync...");
		bt_addr_le_copy(&sync_create_param.addr, &per_addr);
		sync_create_param.options = 0;
		sync_create_param.sid = per_sid;
		sync_create_param.skip = 0;
		/* Multiple PA interval with retry count and convert to unit of 10 ms */
		sync_create_param.timeout =
			(per_interval_us * PA_RETRY_COUNT) / (10 * USEC_PER_MSEC);
		sem_timeout_us = per_interval_us * PA_RETRY_COUNT;
		err = bt_le_per_adv_sync_create(&sync_create_param, &sync);
		if (err) {
			printk("failed (err %d)\n", err);
			return 0;
		}
		printk("success.\n");

		printk("Waiting for periodic sync...\n");
		err = k_sem_take(&sem_per_sync, K_USEC(sem_timeout_us));
		if (err) {
			printk("failed (err %d)\n", err);

			printk("Deleting Periodic Advertising Sync...");
			err = bt_le_per_adv_sync_delete(sync);
			if (err) {
				printk("failed (err %d)\n", err);
				return 0;
			}
			continue;
		}
		printk("Periodic sync established.\n");

		printk("Waiting for BIG info...\n");
		err = k_sem_take(&sem_per_big_info, K_USEC(sem_timeout_us));
		if (err) {
			printk("failed (err %d)\n", err);

			if (per_adv_lost) {
				continue;
			}

			printk("Deleting Periodic Advertising Sync...");
			err = bt_le_per_adv_sync_delete(sync);
			if (err) {
				printk("failed (err %d)\n", err);
				return 0;
			}
			continue;
		}
		printk("Periodic sync established.\n");

	big_sync_create:
		printk("Create BIG Sync...\n");
		err = bt_iso_big_sync(sync, &big_sync_param, &big);
		if (err) {
			printk("failed (err %d)\n", err);
			return 0;
		}
		printk("success.\n");

		for (uint8_t chan = 0U; chan < BIS_ISO_CHAN_COUNT; chan++) {
			printk("Waiting for BIG sync chan %u...\n", chan);
			err = k_sem_take(&sem_big_sync, TIMEOUT_SYNC_CREATE);
			if (err) {
				break;
			}
			printk("BIG sync chan %u successful.\n", chan);
		}
		if (err) {
			printk("failed (err %d)\n", err);

			printk("BIG Sync Terminate...");
			err = bt_iso_big_terminate(big);
			if (err) {
				printk("failed (err %d)\n", err);
				return 0;
			}
			printk("done.\n");

			goto per_sync_lost_check;
		}
		printk("BIG sync established.\n");

		for (uint8_t chan = 0U; chan < BIS_ISO_CHAN_COUNT; chan++) {
			printk("Waiting for BIG sync lost chan %u...\n", chan);
			err = k_sem_take(&sem_big_sync_lost, K_FOREVER);
			if (err) {
				printk("failed (err %d)\n", err);
				return 0;
			}
			printk("BIG sync lost chan %u.\n", chan);
		}
		printk("BIG sync lost.\n");

	per_sync_lost_check:
		printk("Check for periodic sync lost...\n");
		err = k_sem_take(&sem_per_sync_lost, K_NO_WAIT);
		if (err) {
			/* Periodic Sync active, go back to creating BIG Sync */
			goto big_sync_create;
		}
		printk("Periodic sync lost.\n");
	} while (true);
}
