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

#include <debug.h>
#include <pthread.h>

#include "InputHandler.h"
#include "MediaPlayerImpl.h"
#include "utils/MediaUtils.h"
#include "Decoder.h"
#include "Demuxer.h"


#ifndef CONFIG_HANDLER_STREAM_BUFFER_SIZE
#define CONFIG_HANDLER_STREAM_BUFFER_SIZE 4096
#endif

#ifndef CONFIG_HANDLER_STREAM_BUFFER_THRESHOLD
#define CONFIG_HANDLER_STREAM_BUFFER_THRESHOLD 2048
#endif

#ifndef CONFIG_HANDLER_PRELOAD_BUFFER_SIZE
#define CONFIG_HANDLER_PRELOAD_BUFFER_SIZE 1024
#endif

namespace media {
namespace stream {

InputHandler::InputHandler() :
	mInputDataSource(nullptr),
	mDecoder(nullptr),
	mWorker(0),
	mIsWorkerAlive(false),
	mPreloadData(nullptr),
	mPreloadLength(0),
	mState(BUFFER_STATE_EMPTY),
	mTotalBytes(0)
{
}

void InputHandler::setInputDataSource(std::shared_ptr<InputDataSource> source)
{
	mInputDataSource = source;
}

bool InputHandler::doStandBy()
{
	auto mp = getPlayer();
	if (!mp) {
		meddbg("get player handle failed!\n");
		return false;
	}

	std::thread wk = std::thread([=]() {
		medvdbg("InputHandler::doStandBy thread enter\n");
		player_event_t event;
		if (mInputDataSource->open()) {
			event = PLAYER_EVENT_SOURCE_PREPARED;
		} else {
			event = PLAYER_EVENT_SOURCE_OPEN_FAILED;
		}
		mp->notifyAsync(event);
		medvdbg("InputHandler::doStandBy thread exit\n");
	});

	wk.detach();
	return true;
}

bool InputHandler::open()
{
	if (!getStreamBuffer()) {
		auto streamBuffer = StreamBuffer::Builder()
								.setBufferSize(CONFIG_HANDLER_STREAM_BUFFER_SIZE)
								.setThreshold(CONFIG_HANDLER_STREAM_BUFFER_THRESHOLD)
								.build();

		if (!streamBuffer) {
			meddbg("streamBuffer is nullptr!\n");
			return false;
		}

		setStreamBuffer(streamBuffer);
	}

	if (mInputDataSource->open()) {
		/* Preload data from source and parse it to get container format.
		 * Actually, we have obtained the container format when DataSource opening,
		 * but we can not get the format information via any DataSoruce interface.
		 * (Maybe there should be such DataSoruce interface provided in future.)
		 */
		audio_container_t audioContainer;
		if (!getContainerFormat(&audioContainer)) {
			meddbg("get container format failed!\n");
			return false;
		}

		/* If the datasoruce stream is in any container format,
		 * then a demuxer is necessary.
		 */
		if (audioContainer != AUDIO_CONTAINER_NONE) {
			if (!registerDemux(audioContainer)) {
				meddbg("register demuxer failed!\n");
				return false;
			}
		}

		/* Media f/w playback supports only mono and stereo.
		 * In case of multiple channel audio, we ask decoder always outputting stereo PCM data.
		 */
		if (mInputDataSource->getChannels() > 2) {
			medvdbg("Set multiple channel %u to stereo forcely!\n", mInputDataSource->getChannels());
			mInputDataSource->setChannels(2);
		}

		if (registerDecoder(mInputDataSource->getAudioType(), mInputDataSource->getChannels(), mInputDataSource->getSampleRate())) {
			return start();
		}
	}

	return false;
}

bool InputHandler::close()
{
	stop();
	unregisterDecoder();
	unregisterDemux();
	if (mPreloadData) {
		delete[] mPreloadData;
		mPreloadData = nullptr;
	}
	return mInputDataSource->close();
}

ssize_t InputHandler::read(unsigned char *buf, size_t size)
{
	size_t rlen = 0;

	start(); // Auto start

	if (mBufferReader) {
		rlen = mBufferReader->read(buf, size);
	}

	return (ssize_t)rlen;
}

bool InputHandler::start()
{
	if (!mInputDataSource->isPrepared()) {
		return false;
	}

	createWorker();
	return true;
}

bool InputHandler::stop()
{
	destroyWorker();
	return true;
}

void InputHandler::createWorker()
{
	medvdbg("InputHandler::createWorker()\n");
	if (mStreamBuffer && !mIsWorkerAlive) {
		mStreamBuffer->reset();
		mState = BUFFER_STATE_EMPTY;
		mTotalBytes = 0;
		mIsWorkerAlive = true;

		long stackSize = CONFIG_INPUT_DATASOURCE_STACKSIZE;
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, stackSize);
		int ret = pthread_create(&mWorker, &attr, static_cast<pthread_startroutine_t>(InputHandler::workerMain), this);
		if (ret != OK) {
			meddbg("Fail to create DataSourceWorker thread, return value : %d\n", ret);
			mIsWorkerAlive = false;
			return;
		}
		pthread_setname_np(mWorker, "InputHandlerWorker");
	}
}

void InputHandler::destroyWorker()
{
	medvdbg("InputHandler::destroyWorker()\n");
	if (mIsWorkerAlive) {
		// Setup flag,
		mIsWorkerAlive = false;

		// Worker may be blocked in buffer writing.
		mBufferWriter->setEndOfStream();

		// Wake worker up,
		wakenWorker();

		// Join thread.
		pthread_join(mWorker, NULL);
	}
}

void *InputHandler::workerMain(void *arg)
{
	auto stream = static_cast<InputHandler *>(arg);
	auto worker = stream->mInputDataSource;

	while (stream->mIsWorkerAlive) {
		// Waken up by a reading/stopping operation
		stream->sleepWorker();

		// Worker may be stoped
		if (!stream->mIsWorkerAlive) {
			break;
		}

		auto size = stream->sizeOfSpace();
		if (size > 0) {
			unsigned char *buf;
			if (stream->mPreloadData) {
				size = stream->mPreloadLength;
				buf = stream->mPreloadData;
				stream->mPreloadData = nullptr;
			} else {
				buf = new unsigned char[size];
				if ((size = worker->read(buf, size)) <= 0) {
					// Error occurred, or inputting finished
					stream->mBufferWriter->setEndOfStream();
					delete[] buf;
					break;
				}
			}

			stream->writeToStreamBuffer(buf, size);
			delete[] buf;
		}
	}

	return NULL;
}

void InputHandler::sleepWorker()
{
	bool bEOS = mBufferReader->isEndOfStream();
	size_t spaces = mBufferWriter->sizeOfSpace();

	std::unique_lock<std::mutex> lock(mMutex);
	// In case of EOS or overrun, sleep worker.
	if (mIsWorkerAlive && (bEOS || (spaces == 0))) {
		mCondv.wait(lock);
	}
}

void InputHandler::wakenWorker()
{
	std::lock_guard<std::mutex> lock(mMutex);
	mCondv.notify_one();
}

void InputHandler::setStreamBuffer(std::shared_ptr<StreamBuffer> streamBuffer)
{
	if (mStreamBuffer) {
		mStreamBuffer->setObserver(nullptr);
		mBufferReader = nullptr;
		mBufferWriter = nullptr;
	}

	mStreamBuffer = streamBuffer;

	if (mStreamBuffer) {
		mStreamBuffer->setObserver(this);
		mBufferReader = std::make_shared<StreamBufferReader>(mStreamBuffer);
		mBufferWriter = std::make_shared<StreamBufferWriter>(mStreamBuffer);
	}
}

void InputHandler::setBufferState(buffer_state_t state)
{
	if (mState != state) {
		mState = state;
		auto mp = getPlayer();
		if (mp) {
			mp->notifyObserver(PLAYER_OBSERVER_COMMAND_BUFFER_STATECHANGED, (int)state);
		}
	}
}

void InputHandler::onBufferOverrun()
{
	auto mp = getPlayer();
	if (mp) {
		mp->notifyObserver(PLAYER_OBSERVER_COMMAND_BUFFER_OVERRUN);
	}
}

void InputHandler::onBufferUnderrun()
{
	auto mp = getPlayer();
	if (mp) {
		mp->notifyObserver(PLAYER_OBSERVER_COMMAND_BUFFER_UNDERRUN);
	}
}

void InputHandler::onBufferUpdated(ssize_t change, size_t current)
{
	if (change < 0) {
		// Reading wake worker up
		wakenWorker();
	}

	if (current == 0) {
		setBufferState(BUFFER_STATE_EMPTY);
	} else if (current == mStreamBuffer->getBufferSize()) {
		setBufferState(BUFFER_STATE_FULL);
	} else if (current >= mStreamBuffer->getThreshold()) {
		setBufferState(BUFFER_STATE_BUFFERED);
	} else {
		setBufferState(BUFFER_STATE_BUFFERING);
	}

	if (change > 0) {
		mTotalBytes += change;
		if (mTotalBytes > INT_MAX) {
			mTotalBytes = 0;
			meddbg("Too huge value: %u, set 0 to prevent overflow\n", mTotalBytes);
		}

		auto mp = getPlayer();
		if (mp) {
			mp->notifyObserver(PLAYER_OBSERVER_COMMAND_BUFFER_UPDATED, mTotalBytes);
		}
	}
}

size_t InputHandler::sizeOfSpace()
{
	// if has demuxer
	if (mDemuxer) {
		return mDemuxer->sizeOfSpace();
	}

	// if has decoder
	// return space size of decoder buffer
	// TODO:

	// return PCM buffer space size
	return mBufferWriter->sizeOfSpace();
}

ssize_t InputHandler::writeToStreamBuffer(unsigned char *buf, size_t size)
{
	assert(buf != nullptr);

	if (mDemuxer) {
		mDemuxer->pushData(buf, size);

		if (!mDemuxer->isReady()) {
			if (mDemuxer->prepare() < 0) {
				medwdbg("Prepare demuxer failed!\n");
				return size;
			}
		}

		auto lenES  = mDemuxer->pullData(buf, size);
		if (lenES < 0) {
			medwdbg("Can not pull any ES data currently! ret: %d\n", lenES);
			return size;
		}
		// update `size` to real ES data length
		size = (size_t)lenES;
	}

	size_t written = 0;

	if (mDecoder) {
		size_t push = 0;
		while (push < size) {
			size_t temp = mDecoder->pushData(buf + push, size - push);
			if (!temp) {
				meddbg("decode push data failed!\n");
				return EOF;
			}
			push += temp;

			while (1) {
				// Reuse free space: buf[0~push)
				size_t pcmlen = push & ~0x1;
				if (!getDecodeFrames(buf, &pcmlen)) {
					// Normal case: break and push more data...
					break;
				}
				// Write PCM data to input stream buffer.
				written += mBufferWriter->write(buf, pcmlen);
			}
		}
	} else {
		written = mBufferWriter->write(buf, size);
	}

	return (ssize_t)written;
}

bool InputHandler::getContainerFormat(audio_container_t *audioContainer)
{
	mPreloadLength = CONFIG_HANDLER_PRELOAD_BUFFER_SIZE;
	mPreloadData = new unsigned char[mPreloadLength];
	if (!mPreloadData) {
		meddbg("memory allocation failed!\n");
		return false;
	}

	// preload data from source
	auto readLen = mInputDataSource->read(mPreloadData, mPreloadLength);
	if ((size_t)readLen != mPreloadLength) {
		meddbg("Can not preload enough data required! read:%ld\n", readLen);
		delete[] mPreloadData;
		mPreloadData = nullptr;
		return false;
	}

	*audioContainer = media::utils::getAudioContainerFromStream(mPreloadData, mPreloadLength);
	return true;
}

bool InputHandler::registerDemux(audio_container_t audioContainer)
{
	mDemuxer = Demuxer::create(audioContainer);
	if (!mDemuxer) {
		meddbg("Create demuxer of audioContainer %d failed!\n", audioContainer);
		return false;
	}
	return true;
}

void InputHandler::unregisterDemux()
{
	mDemuxer = nullptr;
}

bool InputHandler::registerDecoder(audio_type_t audioType, unsigned int channels, unsigned int sampleRate)
{
	switch (audioType) {
	case AUDIO_TYPE_MP3:
	case AUDIO_TYPE_AAC:
	case AUDIO_TYPE_WAVE:
	case AUDIO_TYPE_OPUS: {
		auto decoder = Decoder::create(audioType, channels, sampleRate);
		if (!decoder) {
			meddbg("%s[line : %d] Fail : Decoder::create failed\n", __func__, __LINE__);
			return false;
		}
		mDecoder = decoder;
		return true;
	}
	case AUDIO_TYPE_PCM:
		medvdbg("AUDIO_TYPE_PCM does not need the decoder\n");
		return true;
	case AUDIO_TYPE_FLAC:
		/* To be supported */
	default:
		meddbg("%s[line : %d] Fail : type %d is not supported\n", __func__, __LINE__, audioType);
		return false;
	}
}

void InputHandler::unregisterDecoder()
{
	mDecoder = nullptr;
}

size_t InputHandler::getDecodeFrames(unsigned char *buf, size_t *size)
{
	unsigned int sampleRate = 0;
	unsigned short channels = 0;

	if (mDecoder->getFrame(buf, size, &sampleRate, &channels)) {
		medvdbg("size : %u samplerate : %d channels : %d\n", *size, sampleRate, channels);
		return *size;
	}

	return 0;
}

} // namespace stream
} // namespace media
