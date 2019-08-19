/* ****************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef __MEDIA_DEMUXER_H
#define __MEDIA_DEMUXER_H

#include <tinyara/config.h>
#include <stdio.h>
#include <memory>
#include <media/MediaTypes.h>

namespace media {

// Demuxer Error Codes
enum demuxer_error_e : int {
	DEMUXER_ERROR_OUT_OF_MEMORY = -5,
	DEMUXER_ERROR_SYNC_FAILED = -4,
	DEMUXER_ERROR_WANT_DATA = -3,
	DEMUXER_ERROR_NOT_READY = -2,
	DEMUXER_ERROR_UNKNOWN = -1,
	DEMUXER_ERROR_NONE = 0 // No Error
};

typedef enum demuxer_error_e demuxer_error_t;

class Demuxer
{
public:
	// create concrete demuxer instance according to the given container type.
	static std::shared_ptr<Demuxer> create(audio_container_t containerType);
	// constructor & destructor
	Demuxer() = delete;
	Demuxer(audio_container_t containerType);
	virtual ~Demuxer();
	// setters & getters
	audio_container_t getContainerType(void) { return mContainerType; }
	void setParam(void *param) { mParam = param; }
	void *getParam(void) { return mParam; }

public:
	// initialize Demuxer, allocate resources
	virtual bool initialize(void) = 0;
	// push stream data into demuxer buffer
	// on success, return number of bytes of data accepted by demuxer
	//    it may be less than input size when demuxer buffer is full.
	// on failure, return negative value (see demuxer_error_t)
	virtual ssize_t pushData(unsigned char *buf, size_t size) = 0;
	// pull audio elementary stream data from demuxer
	// on success, return number of bytes of data saved in `buf`
	//    it may be less than expected size when demuxer require more input data,
	//    in case of error code: DEMUXER_ERROR_WANT_DATA, push more data and pull again.
	// on failure, return negative value (see demuxer_error_t)
	virtual ssize_t pullData(unsigned char *buf, size_t size, void *param = nullptr) = 0;
	// space size available for push
	virtual size_t sizeOfSpace(void) = 0;
	// prepare Demuxer, preparse stream data ahead if necessary
	// on success, return 0
	// on failure, return negative value (see demuxer_error_t)
	virtual int prepare(void) = 0;
	// check if Demuxer is ready (prepare succeed)
	virtual bool isReady(void) = 0;
	// get audio type of the audio elementary stream
	virtual audio_type_t getAudioType(void *param = nullptr) = 0;

private:
	audio_container_t mContainerType;
	void *mParam;
};

} // namespace media

#endif /* __MEDIA_DEMUXER_H */
