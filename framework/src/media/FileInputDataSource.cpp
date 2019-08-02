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
		unsigned int channel = 0;
		unsigned int sampleRate;
		audio_format_type_t pcmFormat;
		audio_container_t audioContainer;
		audio_type_t audioType = AUDIO_TYPE_INVALID;

		mFp = fopen(mDataPath.c_str(), "rb");
		if (!mFp) {
			meddbg("file open failed error : %d\n", errno);
			return false;
		}

		audioContainer = utils::getAudioContainerFromPath(mDataPath);
		if (audioContainer == AUDIO_CONTAINER_NONE || audioContainer == AUDIO_CONTAINER_UNKNOWN) {
			audioType = utils::getAudioTypeFromPath(mDataPath);
		} else {
			// get audio type with container parsing methods
			meddbg("get audio type with container(%d) parsing methods\n", audioContainer); ////////////// debug
			switch (audioContainer) {
			case AUDIO_CONTAINER_MPEG2TS: {
				#define PREPARE_BUFFER_BASE_SIZE 4096
				#define PREPARE_BUFFER_MORE_SIZE 2048
				int i;
				size_t bufferSize;
				unsigned char *buffer = NULL;
				for (i = 0; i < 3; i++) {
					bufferSize = PREPARE_BUFFER_BASE_SIZE + (i * PREPARE_BUFFER_MORE_SIZE);
					buffer = new unsigned char[bufferSize];
					if (!buffer) {
						meddbg("run out of memory! size %u\n", bufferSize);
						return false;
					}
					// read file
					fseek(mFp, 0, SEEK_SET);
					bufferSize = fread(buffer, sizeof(unsigned char), bufferSize, mFp);
					fseek(mFp, 0, SEEK_SET);
					// parse ts
					bool ret = utils::ts_parsing(buffer, bufferSize, &audioType, &channel, &sampleRate, &pcmFormat);
					delete[] buffer;
					if (ret) {
						meddbg("ts_parsing audioType %d, channel %u, sampleRate %u, pcmFormat %d\n", audioType, channel, sampleRate, pcmFormat); ///////// verbos
						break;
					}
				}
			} break;

			default:
				break;
			}
		}

		setAudioType(audioType);
		switch (audioType) {
		case AUDIO_TYPE_MP3:
		case AUDIO_TYPE_AAC:
			if (channel == 0 && !utils::header_parsing(mFp, audioType, &channel, &sampleRate, NULL)) {
				meddbg("header parsing failed\n");
				channel = 2;
				sampleRate = 48000;
				// for test ts aac audio stream
				//return false;
			}
			setSampleRate(sampleRate);
			setChannels(channel);
			break;
		case AUDIO_TYPE_WAVE:
			if (channel == 0 && !utils::header_parsing(mFp, audioType, &channel, &sampleRate, &pcmFormat)) {
				meddbg("header parsing failed\n");
				return false;
			}
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
