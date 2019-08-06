/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "MediaUtils.h"
#include <debug.h>
#include <errno.h>

#include "../demux/mpeg2ts/TSParser.h"

namespace media {
namespace utils {

#ifdef __GNUC__
#define POPCOUNT(x) __builtin_popcount(x)
#else
#define POPCOUNT(x) popcount(x)
#endif

// Mine-Type for audio stream
static const std::string AAC_MIME_TYPE = "audio/aac";
static const std::string AACP_MIME_TYPE = "audio/aacp";
static const std::string MPEG_MIME_TYPE = "audio/mpeg";
static const std::string MP4_MIME_TYPE = "audio/mp4";
static const std::string OPUS_MIME_TYPE = "audio/opus";

#if 0
static const unsigned int ulTable_MPEG32[256] = {
	0x00000000L, 0x04C11DB7L, 0x09823B6EL, 0x0D4326D9L,
	0x130476DCL, 0x17C56B6BL, 0x1A864DB2L, 0x1E475005L,
	0x2608EDB8L, 0x22C9F00FL, 0x2F8AD6D6L, 0x2B4BCB61L,
	0x350C9B64L, 0x31CD86D3L, 0x3C8EA00AL, 0x384FBDBDL,
	0x4C11DB70L, 0x48D0C6C7L, 0x4593E01EL, 0x4152FDA9L,
	0x5F15ADACL, 0x5BD4B01BL, 0x569796C2L, 0x52568B75L,
	0x6A1936C8L, 0x6ED82B7FL, 0x639B0DA6L, 0x675A1011L,
	0x791D4014L, 0x7DDC5DA3L, 0x709F7B7AL, 0x745E66CDL,
	0x9823B6E0L, 0x9CE2AB57L, 0x91A18D8EL, 0x95609039L,
	0x8B27C03CL, 0x8FE6DD8BL, 0x82A5FB52L, 0x8664E6E5L,
	0xBE2B5B58L, 0xBAEA46EFL, 0xB7A96036L, 0xB3687D81L,
	0xAD2F2D84L, 0xA9EE3033L, 0xA4AD16EAL, 0xA06C0B5DL,
	0xD4326D90L, 0xD0F37027L, 0xDDB056FEL, 0xD9714B49L,
	0xC7361B4CL, 0xC3F706FBL, 0xCEB42022L, 0xCA753D95L,
	0xF23A8028L, 0xF6FB9D9FL, 0xFBB8BB46L, 0xFF79A6F1L,
	0xE13EF6F4L, 0xE5FFEB43L, 0xE8BCCD9AL, 0xEC7DD02DL,
	0x34867077L, 0x30476DC0L, 0x3D044B19L, 0x39C556AEL,
	0x278206ABL, 0x23431B1CL, 0x2E003DC5L, 0x2AC12072L,
	0x128E9DCFL, 0x164F8078L, 0x1B0CA6A1L, 0x1FCDBB16L,
	0x018AEB13L, 0x054BF6A4L, 0x0808D07DL, 0x0CC9CDCAL,
	0x7897AB07L, 0x7C56B6B0L, 0x71159069L, 0x75D48DDEL,
	0x6B93DDDBL, 0x6F52C06CL, 0x6211E6B5L, 0x66D0FB02L,
	0x5E9F46BFL, 0x5A5E5B08L, 0x571D7DD1L, 0x53DC6066L,
	0x4D9B3063L, 0x495A2DD4L, 0x44190B0DL, 0x40D816BAL,
	0xACA5C697L, 0xA864DB20L, 0xA527FDF9L, 0xA1E6E04EL,
	0xBFA1B04BL, 0xBB60ADFCL, 0xB6238B25L, 0xB2E29692L,
	0x8AAD2B2FL, 0x8E6C3698L, 0x832F1041L, 0x87EE0DF6L,
	0x99A95DF3L, 0x9D684044L, 0x902B669DL, 0x94EA7B2AL,
	0xE0B41DE7L, 0xE4750050L, 0xE9362689L, 0xEDF73B3EL,
	0xF3B06B3BL, 0xF771768CL, 0xFA325055L, 0xFEF34DE2L,
	0xC6BCF05FL, 0xC27DEDE8L, 0xCF3ECB31L, 0xCBFFD686L,
	0xD5B88683L, 0xD1799B34L, 0xDC3ABDEDL, 0xD8FBA05AL,
	0x690CE0EEL, 0x6DCDFD59L, 0x608EDB80L, 0x644FC637L,
	0x7A089632L, 0x7EC98B85L, 0x738AAD5CL, 0x774BB0EBL,
	0x4F040D56L, 0x4BC510E1L, 0x46863638L, 0x42472B8FL,
	0x5C007B8AL, 0x58C1663DL, 0x558240E4L, 0x51435D53L,
	0x251D3B9EL, 0x21DC2629L, 0x2C9F00F0L, 0x285E1D47L,
	0x36194D42L, 0x32D850F5L, 0x3F9B762CL, 0x3B5A6B9BL,
	0x0315D626L, 0x07D4CB91L, 0x0A97ED48L, 0x0E56F0FFL,
	0x1011A0FAL, 0x14D0BD4DL, 0x19939B94L, 0x1D528623L,
	0xF12F560EL, 0xF5EE4BB9L, 0xF8AD6D60L, 0xFC6C70D7L,
	0xE22B20D2L, 0xE6EA3D65L, 0xEBA91BBCL, 0xEF68060BL,
	0xD727BBB6L, 0xD3E6A601L, 0xDEA580D8L, 0xDA649D6FL,
	0xC423CD6AL, 0xC0E2D0DDL, 0xCDA1F604L, 0xC960EBB3L,
	0xBD3E8D7EL, 0xB9FF90C9L, 0xB4BCB610L, 0xB07DABA7L,
	0xAE3AFBA2L, 0xAAFBE615L, 0xA7B8C0CCL, 0xA379DD7BL,
	0x9B3660C6L, 0x9FF77D71L, 0x92B45BA8L, 0x9675461FL,
	0x8832161AL, 0x8CF30BADL, 0x81B02D74L, 0x857130C3L,
	0x5D8A9099L, 0x594B8D2EL, 0x5408ABF7L, 0x50C9B640L,
	0x4E8EE645L, 0x4A4FFBF2L, 0x470CDD2BL, 0x43CDC09CL,
	0x7B827D21L, 0x7F436096L, 0x7200464FL, 0x76C15BF8L,
	0x68860BFDL, 0x6C47164AL, 0x61043093L, 0x65C52D24L,
	0x119B4BE9L, 0x155A565EL, 0x18197087L, 0x1CD86D30L,
	0x029F3D35L, 0x065E2082L, 0x0B1D065BL, 0x0FDC1BECL,
	0x3793A651L, 0x3352BBE6L, 0x3E119D3FL, 0x3AD08088L,
	0x2497D08DL, 0x2056CD3AL, 0x2D15EBE3L, 0x29D4F654L,
	0xC5A92679L, 0xC1683BCEL, 0xCC2B1D17L, 0xC8EA00A0L,
	0xD6AD50A5L, 0xD26C4D12L, 0xDF2F6BCBL, 0xDBEE767CL,
	0xE3A1CBC1L, 0xE760D676L, 0xEA23F0AFL, 0xEEE2ED18L,
	0xF0A5BD1DL, 0xF464A0AAL, 0xF9278673L, 0xFDE69BC4L,
	0x89B8FD09L, 0x8D79E0BEL, 0x803AC667L, 0x84FBDBD0L,
	0x9ABC8BD5L, 0x9E7D9662L, 0x933EB0BBL, 0x97FFAD0CL,
	0xAFB010B1L, 0xAB710D06L, 0xA6322BDFL, 0xA2F33668L,
	0xBCB4666DL, 0xB8757BDAL, 0xB5365D03L, 0xB1F740B4L
};

unsigned int CRC32_MPEG2(unsigned char *data, unsigned int length)
{
	unsigned int ulCRC;
	unsigned char *pbData;

	/* init the start value */
	ulCRC = 0xFFFFFFFF;

	pbData = (unsigned char *)data;

	/* calculate CRC */
	while (length--) {
		ulCRC = ulTable_MPEG32[((ulCRC>>24) ^ *pbData++) & 0xFFL] ^ (ulCRC << 8);
	}
	return ulCRC;
}
#else
unsigned int CRC32_MPEG2(unsigned char *data, unsigned int length)
{
	unsigned char i;
	unsigned int j = 0;
	unsigned int crc = 0xffffffff;

	while ((length--) != 0) {
		crc ^= (unsigned int)data[j] << 24;
		j++;
		for (i = 0; i < 8; ++i) {
			if ((crc & 0x80000000) != 0) {
				crc = (crc << 1) ^ 0x04C11DB7;
			} else {
				crc <<= 1;
			}
		}
	}
	return crc;
}
#endif

void toLowerString(std::string &str)
{
	for (char& c : str) {
		if ('A' <= c && c <= 'Z') {
			c += ('a' - 'A');
		}
	}
}

void toUpperString(std::string &str)
{
	for (char& c : str) {
		if ('a' <= c && c <= 'z') {
			c -= ('a' - 'A');
		}
	}
}

audio_container_t getAudioContainerFromPath(std::string datapath)
{
	std::string basename = datapath.substr(datapath.find_last_of("/") + 1);
	std::string extension;

	if (basename.find(".") == std::string::npos) {
		extension = "";
	} else {
		extension = basename.substr(basename.find_last_of(".") + 1);
	}

	toLowerString(extension);

	if (extension.compare("wav") == 0) {
		return AUDIO_CONTAINER_WAV;
	} else if ((extension.compare("ogg") == 0) || (extension.compare("oga") == 0)) {
		return AUDIO_CONTAINER_OGG;
	} else if ((extension.compare("mp4") == 0) || (extension.compare("m4a") == 0)) {
		return AUDIO_CONTAINER_MP4;
	} else if (extension.compare("ts") == 0) {
		return AUDIO_CONTAINER_MPEG2TS;
	} else {
		auto audioType = getAudioTypeFromPath(datapath);
		if (audioType != AUDIO_TYPE_INVALID) {
			return AUDIO_CONTAINER_NONE;
		}

		medvdbg("unknown (not supported) container\n");
		return AUDIO_CONTAINER_UNKNOWN;
	}
}

audio_container_t getAudioContainerFromStream(const unsigned char *stream, size_t length)
{
	// TODO： install all supported in a static map<container_type, check_method>...
	if (media::stream::TSParser::IsMpeg2Ts(stream, length)) {
		return AUDIO_CONTAINER_MPEG2TS;
	}
	// else try others
	// mp4/ogg...

	return AUDIO_CONTAINER_NONE;
}


audio_type_t getAudioTypeFromPath(std::string datapath)
{
	std::string basename = datapath.substr(datapath.find_last_of("/") + 1);
	std::string extension;

	if (basename.find(".") == std::string::npos) {
		extension = "";
	} else {
		extension = basename.substr(basename.find_last_of(".") + 1);
	}

	toLowerString(extension);

	if (extension.compare("mp3") == 0) {
		medvdbg("audio type : mp3\n");
		return AUDIO_TYPE_MP3;
	} else if ((extension.compare("aac") == 0) || (extension.compare("mp4") == 0)) {
		medvdbg("audio type : aac\n");
		return AUDIO_TYPE_AAC;
	} else if ((extension.compare("opus") == 0)) {
		medvdbg("audio type : opus\n");
		return AUDIO_TYPE_OPUS;
	} else if ((extension.compare("flac") == 0)) {
		medvdbg("audio type : flac\n");
		return AUDIO_TYPE_FLAC;
	} else if ((extension.compare("") == 0) || (extension.compare("pcm") == 0) || (extension.compare("raw") == 0)) {
		medvdbg("audio type : pcm\n");
		return AUDIO_TYPE_PCM;
	} else if (extension.compare(AUDIO_EXT_TYPE_WAV) == 0) {
		medvdbg("audio type : wav\n");
		return AUDIO_TYPE_WAVE;
	} else if (extension.compare("ts") == 0) {
		medvdbg("audio type : ts\n");
		return AUDIO_TYPE_AAC;
	} else {
		medvdbg("audio type : unknown\n");
		return AUDIO_TYPE_INVALID;
	}
}

audio_type_t getAudioTypeFromMimeType(std::string &mimeType)
{
	audio_type_t audioType;

	if (mimeType.empty()) {
		medwdbg("empty mime type!\n");
		audioType = AUDIO_TYPE_UNKNOWN;
	} else if ((mimeType.find(AAC_MIME_TYPE) != std::string::npos) ||
			(mimeType.find(AACP_MIME_TYPE) != std::string::npos)) {
		audioType = AUDIO_TYPE_AAC;
	} else if (mimeType.find(MPEG_MIME_TYPE) != std::string::npos) {
		audioType = AUDIO_TYPE_MP3;
	} else if (mimeType.find(MP4_MIME_TYPE) != std::string::npos) {
		audioType = AUDIO_TYPE_AAC;
	} else if (mimeType.find(OPUS_MIME_TYPE) != std::string::npos) {
		audioType = AUDIO_TYPE_OPUS;
	} else {
		meddbg("Unsupported mime type: %s\n", mimeType.c_str());
		audioType = AUDIO_TYPE_UNKNOWN;
	}

	return audioType;
}

bool mp3_header_parsing(unsigned char *header, unsigned int *channel, unsigned int *sampleRate)
{
/**
*mp3_header is AAAAAAAA AAABBCCD EEEEFFGH IIJJKLMM
*A - Frame sync
*B - MPEG Audio version
*...
*F - Sampling rate frequency
*.
*I - Channel Mode
*...
*/
	unsigned char bit;
	unsigned int mpegVersion;

	bit = header[1];
	bit >>= 3;
	bit &= (unsigned char)0x03;
	/* we need B information so Shift header[1] three times to the right, and & 0x03 */
	switch (bit) {
	case 0:
		mpegVersion = 2;
		break;
	case 2:
		mpegVersion = 1;
		break;
	case 3:
		mpegVersion = 0;
		break;
	default:
		medvdbg("Not Supported Format mpeg version : %u\n", mpegVersion);
		return false;
	}

	bit = header[2];
	bit >>= 2;
	bit &= 0x03;
	/* we need F information so Shift header[1] two times to the right, and & 0x03 */
	switch (bit) {
	case 0:
		*sampleRate = AUDIO_SAMPLE_RATE_44100;
		break;
	case 1:
		*sampleRate = AUDIO_SAMPLE_RATE_48000;
		break;
	case 2:
		*sampleRate = AUDIO_SAMPLE_RATE_32000;
		break;
	default:
		medvdbg("Not Supported Format sample rate : %u\n", sampleRate);
		return false;
	}

	*sampleRate >>= mpegVersion;

	bit = header[3];
	bit >>= 6;
	/* we need I information so Shift header[3] six times to the right */
	if (bit <= 2) {
		*channel = 2;
	} else {
		*channel = 1;
	}
	return true;
}

bool aac_header_parsing(unsigned char *header, unsigned int *channel, unsigned int *sampleRate)
{
/**
*aac_header is AAAAAAAA AAAABCCD EEFFFFGH HHIJKLMM MMMMMMMM MMMOOOOO OOOOOOPP
*A - syncword 0xFFF, all bits must be 1
*....
*F - Sampling rate frequency
*..
*H - Channel Mode
*......
*/
	unsigned char bit;
	bit = header[2];
	bit >>= 2;
	bit &= 0x0F;
	/* we need F information so Shift header[2] two times to the right, and & 0x0F */
	switch (bit) {
	case 0:
		*sampleRate = AUDIO_SAMPLE_RATE_96000;
		break;
	case 1:
		*sampleRate = AUDIO_SAMPLE_RATE_88200;
		break;
	case 2:
		*sampleRate = AUDIO_SAMPLE_RATE_64000;
		break;
	case 3:
		*sampleRate = AUDIO_SAMPLE_RATE_48000;
		break;
	case 4:
		*sampleRate = AUDIO_SAMPLE_RATE_44100;
		break;
	case 5:
		*sampleRate = AUDIO_SAMPLE_RATE_32000;
		break;
	case 6:
		*sampleRate = AUDIO_SAMPLE_RATE_24000;
		break;
	case 7:
		*sampleRate = AUDIO_SAMPLE_RATE_22050;
		break;
	case 8:
		*sampleRate = AUDIO_SAMPLE_RATE_16000;
		break;
	case 9:
		*sampleRate = AUDIO_SAMPLE_RATE_12000;
		break;
	case 10:
		*sampleRate = AUDIO_SAMPLE_RATE_11025;
		break;
	case 11:
		*sampleRate = AUDIO_SAMPLE_RATE_8000;
		break;
	case 12:
		*sampleRate = AUDIO_SAMPLE_RATE_7350;
		break;
	default:
		meddbg("Not Supported Format sample rate : %u\n", sampleRate);
		return false;
	}
	bit = header[2];
	bit <<= 2;
	bit |= (header[3] >> 6);
	bit &= 0x07;
	/* we need H information so Shift header[3] six times to the right, and & 0x07 */
	if (bit <= 0 || bit >= 8) {
		meddbg("Invalid value bit : %d\n", bit);
		return false;
	}

	if (bit == 7) {
		*channel = 8;
	} else {
		*channel = (unsigned int)bit;
	}
	return true;
}

bool wave_header_parsing(unsigned char *header, unsigned int *channel, unsigned int *sampleRate, audio_format_type_t *pcmFormat)
{
/**
*wave header is
*Chunk ID    (4byte) / .... (4byte) /            .... (4byte)                /
*.....       (4byte) / .... (4byte) / .. (2byte)   / NumChannels     (2byte) /
*sample Rate (4byte) / .... (4byte) / .. (2byte)   / Bits Per sample (2byte) /
*.....       (4byte) / .... (4byte)
*/
	unsigned short bitPerSample;
	*channel = header[23];
	*channel <<= 8;
	*channel |= header[22];

	*sampleRate = header[27];
	*sampleRate <<= 8;
	*sampleRate |= header[26];
	*sampleRate <<= 8;
	*sampleRate |= header[25];
	*sampleRate <<= 8;
	*sampleRate |= header[24];

	bitPerSample = header[35];
	bitPerSample <<= 8;
	bitPerSample |= header[34];
	/* wave header is Little Endian, so read from right byte */
	switch (bitPerSample) {
	case 8:
		*pcmFormat = AUDIO_FORMAT_TYPE_S8;
		break;
	case 16:
		*pcmFormat = AUDIO_FORMAT_TYPE_S16_LE;
		break;
	case 32:
		*pcmFormat = AUDIO_FORMAT_TYPE_S32_LE;
		break;
	default:
		meddbg("Not Supported Format bit/sample : %u\n", bitPerSample);
		return false;
	}
	return true;
}

bool header_parsing(FILE *fp, audio_type_t audioType, unsigned int *channel, unsigned int *sampleRate, audio_format_type_t *pcmFormat)
{
	unsigned char *header;
	unsigned char tag[2];
	bool isHeader;
	int ret;

	switch (audioType) {
	case AUDIO_TYPE_MP3:
		isHeader = false;
		while (fread(tag, sizeof(unsigned char), 2, fp) == 2) {
			/* 12 bits for MP3 Sync Word(the beginning of the frame) */
			if ((tag[0] == 0xFF) && ((tag[1] & 0xF0) == 0xF0)) {
				isHeader = true;
				break;
			} else {
				/* If isn't the header information, go back 1byte and then check 2bytes again */
				ret = fseek(fp, -1, SEEK_CUR);
				if (ret != OK) {
					meddbg("file seek failed errno : %d\n", errno);
					return false;
				}
			}
		}
		if (isHeader) {
			header = (unsigned char *)malloc(sizeof(unsigned char) * (MP3_HEADER_LENGTH + 1));

			if (header == NULL) {
				meddbg("malloc failed error\n");
				return false;
			}

			ret = fseek(fp, -2, SEEK_CUR);
			if (ret != OK) {
				meddbg("file seek failed errno : %d\n", errno);
				free(header);
				return false;
			}

			ret = fread(header, sizeof(unsigned char), MP3_HEADER_LENGTH, fp);
			if (ret != MP3_HEADER_LENGTH) {
				meddbg("read failed ret : %d\n", ret);
				free(header);
				return false;
			}

			if (!mp3_header_parsing(header, channel, sampleRate)) {
				meddbg("Header parsing failed\n");
				free(header);
				return false;
			}
		} else {
			medvdbg("no header\n");
			return false;
		}
		break;
	case AUDIO_TYPE_AAC:
		isHeader = false;
		while (fread(tag, sizeof(unsigned char), 1, fp) > 0) {
			if (tag[0] == 0xFF) {
				isHeader = true;
				break;
			}
		}
		if (isHeader) {
			header = (unsigned char *)malloc(sizeof(unsigned char) * (AAC_HEADER_LENGTH + 1));
			if (header == NULL) {
				medvdbg("malloc failed error\n");
				return false;
			}

			if (fseek(fp, -1, SEEK_CUR) != 0) {
				meddbg("file seek failed error\n");
				free(header);
				return false;
			}

			if ((fread(header, sizeof(unsigned char), AAC_HEADER_LENGTH, fp) != AAC_HEADER_LENGTH) || !aac_header_parsing(header, channel, sampleRate)) {
				free(header);
				return false;
			}
		} else {
			medvdbg("no header\n");
			return false;
		}
		break;
	case AUDIO_TYPE_WAVE:
		header = (unsigned char *)malloc(sizeof(unsigned char) * (WAVE_HEADER_LENGTH + 1));
		if (header == NULL) {
			medvdbg("malloc failed error\n");
			return false;
		}

		if ((fread(header, sizeof(unsigned char), WAVE_HEADER_LENGTH, fp) != WAVE_HEADER_LENGTH) || !wave_header_parsing(header, channel, sampleRate, pcmFormat)) {
			free(header);
			return false;
		}
		break;
	default:
		medvdbg("does not support header parsing\n");
		return false;
	}

	if (header != NULL) {
		free(header);
	}

	if (fseek(fp, 0, SEEK_SET) != 0) {
		meddbg("file seek failed error\n");
		return false;
	}
	return true;
}

bool header_parsing(unsigned char *buffer, unsigned int bufferSize, audio_type_t audioType, unsigned int *channel, unsigned int *sampleRate, audio_format_type_t *pcmFormat)
{
	unsigned int headPoint;
	unsigned char *header;
	bool isHeader;
	switch (audioType) {
	case AUDIO_TYPE_MP3:
		if (MP3_HEADER_LENGTH > bufferSize) {
			medvdbg("no header\n");
			return false;
		}
		isHeader = false;
		headPoint = 0;
		while (headPoint < bufferSize) {
			/* 12 bits for MP3 Sync Word(the beginning of the frame) */
			if ((buffer[headPoint]) == 0xFF && ((buffer[headPoint + 1] & 0xF0) == 0xF0)) {
				isHeader = true;
				break;
			}
			headPoint++;
		}
		if (isHeader && MP3_HEADER_LENGTH <= bufferSize - headPoint) {
			header = (unsigned char *)malloc(sizeof(unsigned char) * (MP3_HEADER_LENGTH + 1));
			if (header == NULL) {
				medvdbg("malloc failed error\n");
				return false;
			}
			memcpy(header, buffer + headPoint, MP3_HEADER_LENGTH);
			if (!mp3_header_parsing(header, channel, sampleRate)) {
				free(header);
				return false;
			}
		} else {
			medvdbg("no header\n");
			return false;
		}
		break;
	case AUDIO_TYPE_AAC:
		if (AAC_HEADER_LENGTH > bufferSize) {
			medvdbg("no header\n");
			return false;
		}
		isHeader = false;
		headPoint = 0;
		while (headPoint < bufferSize) {
			if (buffer[headPoint] == 0xFF) {
				isHeader = true;
				break;
			}
			headPoint++;
		}
		if (isHeader && AAC_HEADER_LENGTH <= bufferSize - headPoint) {
			header = (unsigned char *)malloc(sizeof(unsigned char) * (AAC_HEADER_LENGTH + 1));
			if (header == NULL) {
				medvdbg("malloc failed error\n");
				return false;
			}
			memcpy(header, buffer + headPoint, MP3_HEADER_LENGTH);
			if (!aac_header_parsing(header, channel, sampleRate)) {
				free(header);
				return false;
			}
		} else {
			medvdbg("no header\n");
			return false;
		}
		break;
	case AUDIO_TYPE_WAVE:
		if (WAVE_HEADER_LENGTH <= bufferSize) {
			header = (unsigned char *)malloc(sizeof(unsigned char) * (WAVE_HEADER_LENGTH + 1));
			if (header == NULL) {
				medvdbg("malloc failed error\n");
				return false;
			}
			memcpy(header, buffer, WAVE_HEADER_LENGTH);
			if (!wave_header_parsing(header, channel, sampleRate, pcmFormat)) {
				free(header);
				return false;
			}
		} else {
			medvdbg("no header\n");
			return false;
		}
		break;
	default:
		medvdbg("does not support header parsing\n");
		return false;
	}

	if (header != NULL) {
		free(header);
	}
	return true;
}

bool ts_parsing(unsigned char *buffer, unsigned int bufferSize, audio_type_t *audioType, unsigned int *channel, unsigned int *sampleRate, audio_format_type_t *pcmFormat)
{
	// create temporary ts parser
	auto tsParser = media::stream::TSParser::create();
	if (!tsParser) {
		meddbg("TSParser::create failed\n");
		return false;
	}

	// push the given (ts) data into tsparser buffer
	size_t ret = tsParser->pushData(buffer, bufferSize);
	if (ret < bufferSize) {
		medwdbg("TSParser accept part of data %u/%u\n", ret, bufferSize);
	}

	// do parsing PAT & PMT
	if (!tsParser->PreParse()) {
		meddbg("TSParser parse failed\n");
		return false;
	}

	// get programs in ts, usually we select the 1th one as default.
	std::vector<unsigned short> programs;
	tsParser->getPrograms(programs);
	medvdbg("There's %lu programs in the given transport stream\n", programs.size());
	if (programs.empty()) {
		meddbg("TSParser didn't find any program! Failed!\n");
		return false;
	}

	// get audio type (from PMT component stream type field)
	*audioType = tsParser->getAudioType(programs[0]);

	// get ES data (we expect the given ts data is enough to form a PES packet)
	unsigned char audioES[64]; // 64 bytes should be enough for header parsing
	size_t audioESLen = tsParser->pullData(audioES, sizeof(audioES), programs[0]);

	return header_parsing(audioES, audioESLen, *audioType, channel, sampleRate, pcmFormat);
}

struct wav_header_s {
	char headerRiff[4]; //"RIFF"
	uint32_t riffSize;
	char headerWave[4]; //"wave"
	char headerFmt[4]; //"fmt "
	uint32_t fmtSize; //16 for pcm
	uint16_t format; //1 for pcm
	uint16_t channels;
	uint32_t sampleRate;
	uint32_t byteRate;
	uint16_t blockAlign;
	uint16_t bitPerSample;
	char headerData[4]; //"data"
	uint32_t dataSize;
};

bool createWavHeader(FILE *fp)
{
	struct wav_header_s *header;
	header = (struct wav_header_s *)malloc(sizeof(struct wav_header_s));
	if (!header) {
		meddbg("fail to malloc buffer\n");
		return false;
	}

	memset(header, 0xff, WAVE_HEADER_LENGTH);
	int ret;
	ret = fwrite(header, sizeof(unsigned char), WAVE_HEADER_LENGTH, fp);
	if (ret != WAVE_HEADER_LENGTH) {
		meddbg("file write failed error %d\n", errno);
		free(header);
		return false;
	}
	if (fseek(fp, WAVE_HEADER_LENGTH, SEEK_SET) != 0) {
		meddbg("file seek failed error\n");
		free(header);
		return false;
	}

	free(header);
	return true;
}

bool writeWavHeader(FILE *fp, unsigned int channel, unsigned int sampleRate, audio_format_type_t pcmFormat, unsigned int fileSize)
{
/**
*wave header is
*Chunk ID 'RIFF' (4byte) / Chunk Size (4byte) / Fomat 'WAVE' (4byte) /
*Chunk ID 'fmt ' (4byte) / Chunk Size (4byte) / Audio Format (2byte) / NumChannels     (2byte) /
*sample Rate     (4byte) / Byte Rate  (4byte) / Block Align  (2byte) / Bits Per sample (2byte) /
*Chunk ID 'data' (4byte) / Chunk Size (4byte)
*/
	if (fseek(fp, 0, SEEK_SET) != 0) {
		meddbg("file seek failed error\n");
		return false;
	}

	uint32_t byteRate = 0;
	uint16_t bitPerSample = 0;
	uint16_t blockAlign = 0;

	switch (pcmFormat) {
	case AUDIO_FORMAT_TYPE_S16_LE:
		bitPerSample = 16;
		break;
	case AUDIO_FORMAT_TYPE_S32_LE:
		bitPerSample = 32;
		break;
	default:
		meddbg("does not support audio format.\n");
		return false;
	}

	blockAlign = channel * (bitPerSample >> 3);
	byteRate = sampleRate * blockAlign;

	struct wav_header_s *header;
	header = (struct wav_header_s *)malloc(sizeof(struct wav_header_s));
	if (header == NULL) {
		meddbg("malloc failed error\n");
		return false;
	}

	strncpy(header->headerRiff, "RIFF", 4);

	header->riffSize = fileSize - 8;

	strncpy(header->headerWave, "WAVE", 4);
	strncpy(header->headerFmt, "fmt ", 4);

	header->fmtSize = 16;
	header->format = 1;
	header->channels = channel;
	header->sampleRate = sampleRate;
	header->byteRate = byteRate;
	header->blockAlign = blockAlign;
	header->bitPerSample = bitPerSample;

	strncpy(header->headerData, "data", 4);

	header->dataSize = fileSize - WAVE_HEADER_LENGTH;

	int ret = 0;
	ret = fwrite(header, sizeof(unsigned char), WAVE_HEADER_LENGTH, fp);

	if (ret != WAVE_HEADER_LENGTH) {
		meddbg("file write failed error %d\n", errno);
		free(header);
		return false;
	}

	free(header);
	return true;
}

#ifndef __GNUC__
static int32_t popcount(uint32_t x)
{
	x -= (x >> 1) & 0x55555555;
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	x = (x + (x >> 4)) & 0x0F0F0F0F;
	x += x >> 8;
	x += x >> 16;
	return x & 0x0000003F;
}
#endif

unsigned int splitChannel(unsigned int layout, const signed short *stream, unsigned int frames, unsigned int channels, ...)
{
	uint32_t ret = 0;
	if (stream == NULL) {
		meddbg("invalid audio stream!\n");
		return ret;
	}

	uint32_t spf = POPCOUNT(layout); // samples per frame
	uint32_t mask, i, j;
	const int16_t *sdata;
	int16_t *buffer;

	va_list ap;
	va_start(ap, channels);

	for (i = 0; i < channels; i++) {
		mask = va_arg(ap, uint32_t);
		buffer = va_arg(ap, int16_t *);

		// Check params validation
		if (POPCOUNT(mask) != 1) {
			meddbg("specified channel must be a single channel! i:%u, mask:0x%x\n", i, mask);
			continue;
		}

		if ((layout & mask) == 0) {
			meddbg("specified channel does not exist! layout: 0x%x, i:%u, mask:0x%x\n", layout, i, mask);
			continue;
		}

		if (buffer == NULL) {
			meddbg("invalid output buffer! i:%u, mask:0x%x\n", i, mask);
			continue;
		}

		sdata = stream + POPCOUNT(layout & (mask - 1));
		for (j = 0; j < frames; j++) {
			*buffer++ = *sdata;
			sdata += spf;
		}

		ret |= mask;
	}

	va_end(ap);
	return ret;
}
} // namespace util
} // namespace media
