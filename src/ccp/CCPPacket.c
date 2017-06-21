#include "CCPNetwork.h"
#include "CCPPacket.h"

#define VARIABLE_NUMBER_MAX_LEN 4

unsigned char readChar(unsigned char **pptr)
{
	unsigned char c = **pptr;
	(*pptr)++;
	return c;
}

unsigned short readShort(unsigned char **pptr)
{
	unsigned char *ptr = *pptr;
	unsigned short value = 256 * (*ptr) + *(ptr + 1);
	*pptr += 2;
	return value;
}

void writeChar(unsigned char **pptr, unsigned char c)
{
	**pptr = c;
	(*pptr)++;
}

void writeShort(unsigned char **pptr, unsigned short value)
{
	**pptr = (unsigned char) (value / 256);
	(*pptr)++;
	**pptr = (unsigned char) (value % 256);
	(*pptr)++;
}

void encodeString(unsigned char **pptr, const char *str, unsigned short strLen)
{
    writeShort(pptr, strLen);
    strncpy((char *) *pptr, str, strLen);
    *pptr += strLen;
}

void decodeString(unsigned char **pptr, char *str)
{
    unsigned short strLen = readShort(pptr);
    strncpy(str, (char *) *pptr, strLen);
    *pptr += strLen;
}

int encodeVariableNumber(unsigned char *buf, unsigned int value)
{
	int rc = 0;

	do
	{
		char d = value % 128;
		value /= 128;
		/* if there are more digits to encode, set the top bit of this digit */
		if (value > 0)
			d |= 0x80;
		buf[rc++] = d;
	} while (value > 0);

	return rc;
}

int decodeVariableNumber(unsigned char *buf, unsigned int *value)
{
    unsigned char uc;
	int multiplier = 1;
	int len = 0;
    unsigned char *ptr = buf;

	*value = 0;

	do
	{
		if (++len > VARIABLE_NUMBER_MAX_LEN)
		{
			return len;
		}

        uc = *ptr++;

		*value += (uc & 127) * multiplier;
		multiplier *= 128;
	} while ((uc & 128) != 0);

	return len;
}

int decodeVariableNumberNetwork(CLIENT_S *c, unsigned int *value, int timeout_ms)
{
    unsigned char uc;
    int multiplier = 1;
    int len = 0;
    int rc = -1;

    *value = 0;

    do
    {
        if (++len > VARIABLE_NUMBER_MAX_LEN)
        {
            return len;
        }

        rc = c->network.ccpread(&c->network, &uc, 1, timeout_ms);
        if (rc != 1)
        {
            if (-1 == rc)
            {
                return rc;
            }
            else
            {
                return len;
            }
        }

        *value += (uc & 127) * multiplier;
        multiplier *= 128;
    } while ((uc & 128) != 0);


    return len;
}

int packetLen(unsigned int remainLen)
{
    int len = 0;
	len += 1;  /* header byte */

	/* now remaining_length field */
	if (remainLen < 128)
		len += 1;
	else if (remainLen < 16384)
		len += 2;
	else if (remainLen < 2097151)
		len += 3;
	else
		len += 4;
	return len;
}

