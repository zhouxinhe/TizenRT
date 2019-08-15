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
	DEMUX_ERROR_UNKNOWN = -1,
	DEMUX_ERROR_WANT_DATA = -2,
	DEMUX_ERROR_SYNC_FAILED = -3,
	DEMUX_ERROR_OUT_OF_MEMORY = -4,
	DEMUX_ERROR_NOT_READY = -5,
	DEMUX_ERROR_NONE = 0 // No Error
};

typedef enum demuxer_error_e demuxer_error_t;

class Demuxer
{
public:
	static std::shared_ptr<Demuxer> create(audio_container_t containerType);
	Demuxer(audio_container_t containerType);
	virtual ~Demuxer();

public:
	bool init(void);
	size_t pushData(unsigned char *buf, size_t size);
	ssize_t pullData(unsigned char *buf, size_t size, void *param);
	size_t sizeOfSpace(void);
	size_t sizeOfData(void);
	bool isFull() { return (sizeOfSpace() == 0); }
	bool isEmpty() { return (sizeOfData() == 0); }
	audio_type_t getAudioType(void *param);
private:
	void *mParam;
};

} // namespace media

#endif /* __MEDIA_DEMUXER_H */
