/*************************************************************************
**                                                                      **
**      Y U B I K E Y  -  Basic LibUSB programming API for the Yubikey	**
**                                                                      **
**      Copyright 2008 Yubico AB					**
**                                                                      **
**      Date		/ Sig / Rev  / History				**
**      2008-06-05	/ J E / 0.00 / Main				**
**                                                                      **
*************************************************************************/

#include <usb.h>		// Rename to avoid clash with windows USBxxx headers
#include "yubikey.h"
#include <ykutil.h>

#define	YUBICO_VID				0x1050
#define	YUBIKEY_PID				0x0010

#define HID_GET_REPORT			0x01
#define HID_SET_REPORT			0x09

#define	FEATURE_RPT_SIZE		8

#define	REPORT_TYPE_FEATURE		0x03

/*************************************************************************
**  function hidSetReport						**
**  Set HID report							**
**                                                                      **
**  int hidSetReport(YUBIKEY *yk, int reportType, int reportNumber,	**
**		     char *buffer, int size)				**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey					**
**	"reportType" is HID report type (in, out or feature)		**
**	"reportNumber" is report identifier				**
**	"buffer" is pointer to in buffer				**
**	"size" is size of the buffer					**
**									**
**	Returns: Nonzero if successful, zero otherwise			**
**                                                                      **
*************************************************************************/

static int hidSetReport(YUBIKEY *yk, int reportType, int reportNumber, char *buffer, int size)
{
    return usb_control_msg(yk, USB_TYPE_CLASS | USB_RECIP_INTERFACE | USB_ENDPOINT_OUT, HID_SET_REPORT,
			   reportType << 8 | reportNumber, 0, buffer, size, 1000) > 0;
}

/*************************************************************************
**  function hidGetReport						**
**  Get HID report							**
**                                                                      **
**  int hidGetReport(YUBIKEY *yk, int reportType, int reportNumber,	**
**		     char *buffer, int size)				**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey					**
**	"reportType" is HID report type (in, out or feature)		**
**	"reportNumber" is report identifier				**
**	"buffer" is pointer to in buffer				**
**	"size" is size of the buffer					**
**									**
**	Returns: Number of bytes read. Zero if failure			**
**                                                                      **
*************************************************************************/

static int hidGetReport(YUBIKEY *yk, int reportType, int reportNumber, char *buffer, int size)
{
  int m = usb_claim_interface(yk, 0);
  printf ("m %d: %s\n", m, usb_strerror ());

    return usb_control_msg(yk, USB_TYPE_CLASS | USB_RECIP_INTERFACE | USB_ENDPOINT_IN, HID_GET_REPORT,
				    reportType << 8 | reportNumber, 0, buffer, size, 1000) > 0;
}

/*************************************************************************
**  function ykInit							**
**  Initiates libUsb and other stuff. Call this one first		**
**                                                                      **
**  void ykInit(void)							**
**                                                                      **
*************************************************************************/

int ykInit(void)
{
	usb_init();

	if (usb_find_busses()) return usb_find_devices();

	return 0;
}

/*************************************************************************
**  function ykOpen							**
**  Opens first Yubikey found for subsequent operations			**
**                                                                      **
**  YUBIKEY ykOpen(void)						**
**                                                                      **
**  Returns: Handle to opened Yubikey					**
**                                                                      **
*************************************************************************/

YUBIKEY *ykOpen(void)
{
	struct usb_bus *bus;
	struct usb_device *dev;

	// Find first instance of the Yubikey

	for (bus = usb_get_busses(); bus; bus = bus->next)
		for (dev = bus->devices; dev; dev = dev->next)
			if (dev->descriptor.idVendor == YUBICO_VID && dev->descriptor.idProduct == YUBIKEY_PID)
				return (YUBIKEY *) usb_open(dev);

	return (YUBIKEY *) 0;
}

/*************************************************************************
**  function ykClose							**
**  Closes open Yubikey handle						**
**                                                                      **
**  void ykClose(void)							**
**                                                                      **
*************************************************************************/

void ykClose(YUBIKEY *yk)
{
	usb_close((usb_dev_handle *) yk);
}

/*************************************************************************
**  function ykGetStatus						**
**  Read the Yubikey status structure					**
**                                                                      **
**  int ykGetStatus(YUBIKEY *yk, STATUS *status, int forceUpdate)	**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey					**
**	"status" is pointer to returned status structure		**
**	"forceUpdate" is set to nonzero to force update of dynamic fields **
**									**
**	Returns: Nonzero if successful, zero otherwise			**
**                                                                      **
*************************************************************************/

int ykGetStatus(YUBIKEY *yk, STATUS *status, int forceUpdate)
{
	unsigned char buf[FEATURE_RPT_SIZE];

	// Read status structure

	memset(buf, 0, sizeof(buf));

	if (!hidGetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE)) return 0;

	memcpy(status, buf + 1, sizeof(STATUS)); 
	ENDIAN_SWAP(status->touchLevel);

	// If force update, force Yubikey to update its dynamic
	// status value(s)

	if (forceUpdate) {
		memset(buf, 0, sizeof(buf));
		buf[FEATURE_RPT_SIZE - 1] = 0x8a;	// Invalid partition = update only
		hidSetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE);
	}

	return 1;
}

/*************************************************************************
**  function ykWriteSlot						**
**  Writes data to Yubikey slot						**
**                                                                      **
**  static int ykWriteSlot(YUBIKEY *yk, unsigned char slot,		**
**			   const void *buf, int bcnt)			**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey					**
**	"slot" is slot number to write to				**
**	"buf" is pointer to write data buffer				**
**	"bcnt" is number of bytes to write				**
**									**
**	Returns: Nonzero if successful, zero otherwise			**
**                                                                      **
*************************************************************************/

static int ykWriteSlot(YUBIKEY *yk, unsigned char slot, const void *dt, int bcnt)
{
	unsigned char buf[FEATURE_RPT_SIZE], data[SLOT_DATA_SIZE + FEATURE_RPT_SIZE];
	int i, j, pos, part;

	// Insert data and set slot #

	memset(data, 0, sizeof(data));
	memcpy(data, dt, bcnt);
	data[SLOT_DATA_SIZE] = slot;

	// Append slot checksum

	i = getCRC(data, SLOT_DATA_SIZE);
	data[SLOT_DATA_SIZE + 1] = (unsigned char) (i & 0xff);
	data[SLOT_DATA_SIZE + 2] = (unsigned char) (i >> 8);

	// Chop up the data into parts that fits into the payload of a
	// feature report. Set the part number | 0x80 in the end
	// of the feature report. When the Yubikey has processed it,
	// it will clear this byte, signaling that the next part can be sent

	for (pos = 0, part = 0x80; pos < (SLOT_DATA_SIZE + 4); part++) {

		// Ignore parts that are all zeroes except first and last
		// to speed up the transfer

		for (i = j = 0; i < (FEATURE_RPT_SIZE - 1); i++) if (buf[i] = data[pos++]) j = 1;
		if (!j && (part > 0x80) && (pos < SLOT_DATA_SIZE)) continue;

		buf[i] = part;

		if (!hidSetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE)) return 0;

		// When the last byte in the feature report is cleared by
		// the Yubikey, the next part can be sent

		for (i = 0; i < 50; i++) {
			memset(buf, 0, sizeof(buf));
			if (!hidGetReport(yk, REPORT_TYPE_FEATURE, 0, buf, FEATURE_RPT_SIZE)) return 0;	
			if (!buf[FEATURE_RPT_SIZE - 1]) break;
			sleep(10);
		}

		// If timeout, something has gone wrong

		if (i >= 50) return 0;	
	}

	return 1;
}

/*************************************************************************
**  function ykWriteConfig						**
**  Writes key config structure						**
**                                                                      **
**  int ykGetStatus(YUBIKEY *yk, STATUS *status, unsigned char accCode)	**
**                                                                      **
**  Where:                                                              **
**  "yk" is handle to open Yubikey					**
**	"cfg" is pointer to configuration structure. NULL to zap	**
**	"accCode" is current program access code. NULL if none		**
**									**
**	Returns: Nonzero if successful, zero otherwise			**
**                                                                      **
*************************************************************************/

int ykWriteConfig(YUBIKEY *yk, CONFIG *cfg, unsigned char *accCode)
{
	unsigned char buf[sizeof(CONFIG) + ACC_CODE_SIZE];
	STATUS stat;
	int seq;

	// Get current seqence # from status block

	if (!ykGetStatus(yk, &stat, 0)) return 0;

	seq = stat.pgmSeq;

	// Update checksum and insert config block in buffer if present

	memset(buf, 0, sizeof(buf));

	if (cfg) {
		cfg->crc = ~getCRC((unsigned char *) cfg, sizeof(CONFIG) - sizeof(cfg->crc));
		ENDIAN_SWAP(cfg->crc);
		memcpy(buf, cfg, sizeof(CONFIG));
	}

	// Append current access code if present

	if (accCode) memcpy(buf + sizeof(CONFIG), accCode, ACC_CODE_SIZE);

	// Write to Yubikey

	if (!ykWriteSlot(yk, SLOT_CONFIG, buf, sizeof(buf))) return 0;

	// Verify update

	if (!ykGetStatus(yk, &stat, 0)) return 0;

	if (cfg) return stat.pgmSeq != seq;

	return stat.pgmSeq == 0;
}
