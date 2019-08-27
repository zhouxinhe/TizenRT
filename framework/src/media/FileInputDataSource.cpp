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

#include <tinyara/config.h>
#include <stdio.h>
#include <debug.h>

#include <media/FileInputDataSource.h>
#include "utils/MediaUtils.h"

#ifndef CONFIG_DATASOURCE_PREPARSE_BUFFER_SIZE
#define CONFIG_DATASOURCE_PREPARSE_BUFFER_SIZE 4096
#endif

namespace media {
namespace stream {

FileInputDataSource::FileInputDataSource() :
	InputDataSource(),
	mDataPath(""),
	mFp(nullptr)
{
}

FileInputDataSource::FileInputDataSource(const std::string &dataPath) :
	InputDataSource(),
	mDataPath(dataPath),
	mFp(nullptr)
{
}

FileInputDataSource::FileInputDataSource(const FileInputDataSource &source) :
	InputDataSource(source),
	mDataPath(source.mDataPath),
	mFp(source.mFp)
{
}

FileInputDataSource &FileInputDataSource::operator=(const FileInputDataSource &source)
{
	InputDataSource::operator=(source);
	return *this;
}

bool FileInputDataSource::open()
{
	if (!mFp) {
		unsigned int channel;
		unsigned int sampleRate;
		audio_format_type_t pcmFormat = getPcmFormat();
		audio_container_t audioContainer;
		audio_type_t audioType;

		mFp = fopen(mDataPath.c_str(), "rb");
		if (!mFp) {
			meddbg("file open failed error : %d\n", errno);
			return false;
		}

		audioContainer = utils::getAudioContainerFromPath(mDataPath);
		if (audioContainer != AUDIO_CONTAINER_NONE) {
			// has container, demux and parse stream data to get audio type
			size_t bufferSize = CONFIG_DATASOURCE_PREPARSE_BUFFER_SIZE;
			unsigned char *buffer = new unsigned char[bufferSize];
			if (!buffer) {
				meddbg("run out of memory! size %u\n", bufferSize);
				return false;
			}

			size_t readSize = fread(buffer, sizeof(unsigned char), bufferSize, mFp);
			fseek(mFp, 0, SEEK_SET);
			if (readSize != bufferSize) {
				delete[] buffer;
				meddbg("can not read enough data for preparsing! read:%u\n", readSize);
				return false;
			}

			bool ret = utils::stream_parsing(buffer, readSize, audioContainer, &audioType, &channel, &sampleRate, &pcmFormat);
			delete[] buffer;
			if (!ret) {
				meddbg("stream_parsing failed, can not get audio codec type!\n");
				return false;
			}
			medvdbg("audioType %d, channel %u, sampleRate %u, pcmFormat %d\n", audioType, channel, sampleRate, pcmFormat);
			setAudioType(audioType);
			setSampleRate(sampleRate);
			setChannels(channel);
			setPcmFormat(pcmFormat);
			return true;
		}

		// get audio type directly from path
		audioType = utils::getAudioTypeFromPath(mDataPath);
		setAudioType(audioType);
		switch (audioType) {
		case AUDIO_TYPE_MP3:
		case AUDIO_TYPE_AAC:
		case AUDIO_TYPE_WAVE:
			if (!utils::header_parsing(mFp, audioType, &channel, &sampleRate, &pcmFormat)) {
				meddbg("header parsing failed\n");
				return false;
			}
			medvdbg("audioType %d, channel %u, sampleRate %u, pcmFormat %d\n", audioType, channel, sampleRate, pcmFormat);
			setSampleRate(sampleRate);
			setChannels(channel);
			setPcmFormat(pcmFormat);
			break;
		case AUDIO_TYPE_FLAC:
			/* To be supported */
			break;
		default:
			/* Don't set any decoder for unsupported formats */
			break;
		}

		return true;
	}

	/** return true if mFp is not null, because it means it using now */
	return true;
}

bool FileInputDataSource::close()
{
	bool ret = true;
	if (mFp) {
		if (fclose(mFp) == OK) {
			mFp = nullptr;
			medvdbg("close success!!\n");
		} else {
			meddbg("close failed ret : %d error : %d\n", ret, errno);
			ret = false;
		}
	} else {
		meddbg("close failed, mFp is nullptr!!\n");
		ret = false;
	}

	return ret;
}

bool FileInputDataSource::isPrepared()
{
	if (mFp == nullptr) {
		return false;
	}
	return true;
}

ssize_t FileInputDataSource::read(unsigned char *buf, size_t size)
{
	if (!isPrepared()) {
		meddbg("%s[line : %d] Fail : FileInputDataSource is not prepared\n", __func__, __LINE__);
		return EOF;
	}

	if (buf == nullptr) {
		meddbg("%s[line : %d] Fail : buf is nullptr\n", __func__, __LINE__);
		return EOF;
	}

	size_t rlen = fread(buf, sizeof(unsigned char), size, mFp);
	medvdbg("read size : %d\n", rlen);
	if (rlen == 0) {
		/* If file position reaches end of file, it's a normal case, we returns 0 */
		if (feof(mFp)) {
			medvdbg("eof!!!\n");
			return 0;
		}

		/* Otherwise, an error occurred, we also returns error */
		return EOF;
	}

	return rlen;
}

FileInputDataSource::~FileInputDataSource()
{
	if (isPrepared()) {
		close();
	}
}

} // namespace stream
} // namespace media
