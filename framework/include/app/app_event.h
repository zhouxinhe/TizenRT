/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TIZEN_APPFW_EVENT_H__
#define __TIZEN_APPFW_EVENT_H__

#include <app/tizen_error.h>
#include <app/bundle.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file app_event.h
 */

/**
 * @addtogroup CAPI_EVENT_MODULE
 * @{
 */


/**
 * @brief Event handle.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
typedef struct event_handler *event_handler_h;


/**
 * @brief Event callback.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @param[in] event_name The interested event name
 * @param[in] event_data The data of interested event
 * @param[in] user_data The user data set by event_add_event_handler()
 * @see event_add_event_handler
 */
typedef void (*event_cb)(const char *event_name, bundle *event_data, void *user_data);


/**
 * @brief Enumeration for Event Error.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
typedef enum {
	EVENT_ERROR_NONE = TIZEN_ERROR_NONE, /**< Successful */
	EVENT_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER, /**< Invalid parameter */
	EVENT_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY, /**< Out of memory */
	EVENT_ERROR_TIMED_OUT = TIZEN_ERROR_TIMED_OUT, /**< Time out */
	EVENT_ERROR_IO_ERROR = TIZEN_ERROR_IO_ERROR, /**< IO error */
	EVENT_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED /**< Permission denied */
} event_error_e;


/**
 * @brief Definition for system-event of battery : charger status.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks If there is earlier occurrence regarding this event, you will receive the event as soon as you register event handler for this event. You can use this earlier event-data as initial value.
 * @see EVENT_KEY_BATTERY_CHARGER_STATUS
 */
#define SYSTEM_EVENT_BATTERY_CHARGER_STATUS "tizen.system.event.battery_charger_status"


/**
 * @brief Definition for key of SYSTEM_EVENT_BATTERY_CHARGER_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_BATTERY_CHARGER_DISCONNECTED
 * @see EVENT_VAL_BATTERY_CHARGER_CONNECTED
 * @see EVENT_VAL_BATTERY_CHARGER_CHARGING
 * @see EVENT_VAL_BATTERY_CHARGER_DISCHARGING
 */
#define EVENT_KEY_BATTERY_CHARGER_STATUS "battery_charger_status"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_CHARGER_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks charger disconnected
 */
#define EVENT_VAL_BATTERY_CHARGER_DISCONNECTED "disconnected"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_CHARGER_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks charger connected
 */
#define EVENT_VAL_BATTERY_CHARGER_CONNECTED "connected"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_CHARGER_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks charging is enabled
 */
#define EVENT_VAL_BATTERY_CHARGER_CHARGING "charging"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_CHARGER_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks charging is disabled
 */
#define EVENT_VAL_BATTERY_CHARGER_DISCHARGING "discharging"


/**
 * @brief Definition for system-event of battery : level status.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_BATTERY_LEVEL_STATUS
 */
#define SYSTEM_EVENT_BATTERY_LEVEL_STATUS "tizen.system.event.battery_level_status"


/**
 * @brief Definition for key of SYSTEM_EVENT_BATTERY_LEVEL_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_BATTERY_LEVEL_EMPTY
 * @see EVENT_VAL_BATTERY_LEVEL_CRITICAL
 * @see EVENT_VAL_BATTERY_LEVEL_LOW
 * @see EVENT_VAL_BATTERY_LEVEL_HIGH
 * @see EVENT_VAL_BATTERY_LEVEL_FULL
 */
#define EVENT_KEY_BATTERY_LEVEL_STATUS "battery_level_status"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_LEVEL_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BATTERY_LEVEL_EMPTY "empty"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_LEVEL_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BATTERY_LEVEL_CRITICAL "critical"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_LEVEL_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BATTERY_LEVEL_LOW "low"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_LEVEL_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BATTERY_LEVEL_HIGH "high"


/**
 * @brief Definition for value of EVENT_KEY_BATTERY_LEVEL_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BATTERY_LEVEL_FULL "full"


/**
 * @brief Definition for system-event of usb : status of usb connection.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_USB_STATUS
 */
#define SYSTEM_EVENT_USB_STATUS "tizen.system.event.usb_status"


/**
 * @brief Definition for key of SYSTEM_EVENT_USB_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_USB_DISCONNECTED
 * @see EVENT_VAL_USB_CONNECTED
 * @see EVENT_VAL_USB_AVAILABLE
 */
#define EVENT_KEY_USB_STATUS "usb_status"


/**
 * @brief Definition for value of EVENT_KEY_USB_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_USB_DISCONNECTED "disconnected"


/**
 * @brief Definition for value of EVENT_KEY_USB_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks Connected but not-available.
 */
#define EVENT_VAL_USB_CONNECTED "connected"


/**
 * @brief Definition for value of EVENT_KEY_USB_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_USB_AVAILABLE "available"


/**
 * @brief Definition for system-event of ear-jack : status of ear-jack connection.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_EARJACK_STATUS
 */
#define SYSTEM_EVENT_EARJACK_STATUS "tizen.system.event.earjack_status"


/**
 * @brief Definition for key of SYSTEM_EVENT_EARJACK_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_EARJACK_DISCONNECTED
 * @see EVENT_VAL_EARJACK_CONNECTED
 */
#define EVENT_KEY_EARJACK_STATUS "earjack_status"


/**
 * @brief Definition for value of EVENT_KEY_EARJACK_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_EARJACK_DISCONNECTED "disconnected"


/**
 * @brief Definition for value of EVENT_KEY_EARJACK_STATUS.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_EARJACK_CONNECTED "connected"


/**
 * @brief Definition for system-event of display : state of display.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @privilege %http://tizen.org/privilege/display
 * @remarks If you want to receive this event, you must declare this privilege.
 * @see EVENT_KEY_DISPLAY_STATE
 */
#define SYSTEM_EVENT_DISPLAY_STATE "tizen.system.event.display_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_DISPLAY_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_DISPLAY_NORMAL
 * @see EVENT_VAL_DISPLAY_DIM
 * @see EVENT_VAL_DISPLAY_OFF
 */
#define EVENT_KEY_DISPLAY_STATE "display_state"


/**
 * @brief Definition for value of EVENT_KEY_DISPLAY_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_DISPLAY_NORMAL "normal"


/**
 * @brief Definition for value of EVENT_KEY_DISPLAY_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_DISPLAY_DIM "dim"


/**
 * @brief Definition for value of EVENT_KEY_DISPLAY_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_DISPLAY_OFF "off"


/**
 * @brief Definition for system-event of system : boot completion.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks There is no corresponding key/value.
 * @remarks You can treat the initial value as "false" before you receive this event.
 * @remarks If it's already boot-completed state before you register event handler, you can receive the event as soon as you register the event handler.
 */
#define SYSTEM_EVENT_BOOT_COMPLETED "tizen.system.event.boot_completed"


/**
 * @brief Definition for system-event of system : shutdown.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks There is no corresponding key/value.
 * @remarks You can treat the initial value as "false" before you receive this event.
 * @remarks If it's already shutting-down state before you register event handler, you can receive the event as soon as you register the event handler.
*/
#define SYSTEM_EVENT_SYSTEM_SHUTDOWN "tizen.system.event.system_shutdown"


/**
 * @brief Definition for system-event of system : low memory.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_LOW_MEMORY
 */
#define SYSTEM_EVENT_LOW_MEMORY "tizen.system.event.low_memory"


/**
 * @brief Definition for key of SYSTEM_EVENT_LOW_MEMORY.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks If there is earlier occurrence regarding this event, you will receive the event as soon as you register event handler for this event. You can use this earlier event-data as initial value.
 * @see EVENT_VAL_MEMORY_NORMAL
 * @see EVENT_VAL_MEMORY_SOFT_WARNING
 * @see EVENT_VAL_MEMORY_HARD_WARNING
 */
#define EVENT_KEY_LOW_MEMORY "low_memory"


/**
 * @brief Definition for value of EVENT_KEY_LOW_MEMORY.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_MEMORY_NORMAL "normal"


/**
 * @brief Definition for value of EVENT_KEY_LOW_MEMORY.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_MEMORY_SOFT_WARNING "soft_warning"


/**
 * @brief Definition for value of EVENT_KEY_LOW_MEMORY.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_MEMORY_HARD_WARNING "hard_warning"


/**
 * @brief Definition for system-event of wifi : state of wifi.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @privilege %http://tizen.org/privilege/network.get
 * @remarks If you want to receive this event, you must declare this privilege.
 * @see EVENT_KEY_WIFI_STATE
 */
#define SYSTEM_EVENT_WIFI_STATE "tizen.system.event.wifi_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_WIFI_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_WIFI_OFF
 * @see EVENT_VAL_WIFI_ON
 * @see EVENT_VAL_WIFI_CONNECTED
 */
#define EVENT_KEY_WIFI_STATE "wifi_state"


/**
 * @brief Definition for value of EVENT_KEY_WIFI_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_WIFI_OFF "off"


/**
 * @brief Definition for value of EVENT_KEY_WIFI_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_WIFI_ON "on"


/**
 * @brief Definition for value of EVENT_KEY_WIFI_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_WIFI_CONNECTED "connected"


/**
 * @brief Definition for system-event of bluetooth : status of bluetooth.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_BT_STATE
 * @see EVENT_KEY_BT_LE_STATE
 * @see EVENT_KEY_BT_TRANSFERING_STATE
 */
#define SYSTEM_EVENT_BT_STATE "tizen.system.event.bt_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_BT_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_BT_STATE_OFF
 * @see EVENT_VAL_BT_STATE_ON
 */
#define EVENT_KEY_BT_STATE "bt_state"


/**
 * @brief Definition for value of EVENT_KEY_BT_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BT_OFF "off"


/**
 * @brief Definition for value of EVENT_KEY_BT_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BT_ON "on"


/**
 * @brief Definition for key of SYSTEM_EVENT_BT_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_BT_LE_STATE_OFF
 * @see EVENT_VAL_BT_LE_STATE_ON
 */
#define EVENT_KEY_BT_LE_STATE "bt_le_state"


/**
 * @brief Definition for value of EVENT_KEY_BT_LE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BT_LE_OFF "off"


/**
 * @brief Definition for value of EVENT_KEY_BT_LE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BT_LE_ON "on"


/**
 * @brief Definition for key of SYSTEM_EVENT_BT_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks If it's already transferring state before you register this event, you can't receive the event regarding current transfer but you can receive the following transfers.
 * @see EVENT_VAL_BT_NON_TRANSFERING
 * @see EVENT_VAL_BT_TRANSFERING
 */
#define EVENT_KEY_BT_TRANSFERING_STATE "bt_transfering_state"


/**
 * @brief Definition for value of EVENT_KEY_BT_TRANSFERING_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BT_NON_TRANSFERING "non_transfering"


/**
 * @brief Definition for value of EVENT_KEY_BT_TRANSFERING_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_BT_TRANSFERING "transfering"


/**
 * @brief Definition for system-event of location : enable state of location.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_LOCATION_ENABLE_STATE
 */
#define SYSTEM_EVENT_LOCATION_ENABLE_STATE "tizen.system.event.location_enable_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_LOCATION_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_LOCATION_DISABLED
 * @see EVENT_VAL_LOCATION_ENABLED
 */
#define EVENT_KEY_LOCATION_ENABLE_STATE "location_enable_state"


/**
 * @brief Definition for value of EVENT_KEY_LOCATION_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_LOCATION_DISABLED "disabled"


/**
 * @brief Definition for value of EVENT_KEY_LOCATION_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_LOCATION_ENABLED "enabled"


/**
 * @brief Definition for system-event of location : enable state of gps.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_GPS_ENABLE_STATE
 */
#define SYSTEM_EVENT_GPS_ENABLE_STATE "tizen.system.event.gps_enable_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_GPS_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_GPS_DISABLED
 * @see EVENT_VAL_GPS_ENABLED
 */
#define EVENT_KEY_GPS_ENABLE_STATE "gps_enable_state"


/**
 * @brief Definition for value of EVENT_KEY_GPS_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_GPS_DISABLED "disabled"


/**
 * @brief Definition for value of EVENT_KEY_GPS_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_GPS_ENABLED "enabled"


/**
 * @brief Definition for system-event of location : enable state of nps.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_NPS_ENABLE_STATE
 */
#define SYSTEM_EVENT_NPS_ENABLE_STATE "tizen.system.event.nps_enable_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_NPS_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_NPS_DISABLED
 * @see EVENT_VAL_NPS_ENABLED
 */
#define EVENT_KEY_NPS_ENABLE_STATE "nps_enable_state"


/**
 * @brief Definition for value of EVENT_KEY_NPS_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_NPS_DISABLED "disabled"


/**
 * @brief Definition for value of EVENT_KEY_NPS_ENABLE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_NPS_ENABLED "enabled"


/**
 * @brief Definition for system-event of message : incoming msg.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @privilege %http://tizen.org/privilege/message.read
 * @remarks If you want to receive this event, you must declare this privilege.
 * @see EVENT_KEY_MSG_TYPE
 * @see EVENT_KEY_MSG_ID
 */
#define SYSTEM_EVENT_INCOMING_MSG "tizen.system.event.incoming_msg"


/**
 * @brief Definition for key of SYSTEM_EVENT_INCOMING_MSG.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_SMS
 * @see EVENT_VAL_PUSH
 * @see EVENT_VAL_CB
 */
#define EVENT_KEY_MSG_TYPE "msg_type"


/**
 * @brief Definition for value of EVENT_KEY_MSG_TYPE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_SMS "sms"


/**
 * @brief Definition for value of EVENT_KEY_MSG_TYPE.
 * @since_tizen 3.0
 */
#define EVENT_VAL_MMS "mms"


/**
 * @brief Definition for value of EVENT_KEY_MSG_TYPE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_PUSH "push"


/**
 * @brief Definition for value of EVENT_KEY_MSG_TYPE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_CB "cb"


/**
 * @brief Definition for key of SYSTEM_EVENT_INCOMING_MSG.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The value of this key is a string of unsigned int value : new message id.
 */
#define EVENT_KEY_MSG_ID "msg_id"


/**
 * @brief Definition for system-event of message : outgoing msg.
 * @since_tizen 3.0
 * @privilege %http://tizen.org/privilege/message.read
 * @remarks If you want to receive this event, you must declare this privilege.
 * @see EVENT_KEY_OUT_MSG_TYPE
 * @see EVENT_KEY_OUT_MSG_ID
 */
#define SYSTEM_EVENT_OUTGOING_MSG "tizen.system.event.outgoing_msg"


/**
 * @brief Definition for key of SYSTEM_EVENT_OUTGOING_MSG.
 * @since_tizen 3.0
 * @see EVENT_VAL_OUT_MSG_SMS
 * @see EVENT_VAL_OUT_MSG_MMS
 */
#define EVENT_KEY_OUT_MSG_TYPE "msg_type"


/**
 * @brief Definition for value of EVENT_KEY_OUT_MSG_TYPE.
 * @since_tizen 3.0
 */
#define EVENT_VAL_SMS "sms"


/**
 * @brief Definition for value of EVENT_KEY_OUT_MSG_TYPE.
 * @since_tizen 3.0
 */
#define EVENT_VAL_MMS "mms"


/**
 * @brief Definition for key of SYSTEM_EVENT_OUTGOING_MSG.
 * @since_tizen 3.0
 * @remarks The value of this key is a string of unsigned int value : new message id.
 */
#define EVENT_KEY_OUT_MSG_ID "msg_id"


/**
 * @brief Definition for system-event of setting : time changed.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks There is no corresponding key/value.
 * @remarks You can use a @a alarm_get_current_time() API for checking new time after receiving this event.
 */
#define SYSTEM_EVENT_TIME_CHANGED "tizen.system.event.time_changed"


/**
 * @brief Definition for system-event of setting : timezone setting.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_TIME_ZONE
 */
#define SYSTEM_EVENT_TIME_ZONE "tizen.system.event.time_zone"


/**
 * @brief Definition for key of SYSTEM_EVENT_TIME_ZONE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The value of this key is timezone value of tz database, for example, "Asia/Seoul", "America/New_York", refer to the Time Zone Database of IANA.
 */
#define EVENT_KEY_TIME_ZONE "time_zone"


/**
 * @brief Definition for system-event of setting : hour format.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_HOUR_FORMAT
 */
#define SYSTEM_EVENT_HOUR_FORMAT "tizen.system.event.hour_format"


/**
 * @brief Definition for key of SYSTEM_EVENT_HOUR_FORMAT.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_HOURFORMAT_12
 * @see EVENT_VAL_HOURFORMAT_24
 */
#define EVENT_KEY_HOUR_FORMAT "hour_format"


/**
 * @brief Definition for value of EVENT_KEY_HOUR_FORMAT.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_HOURFORMAT_12 "12"


/**
 * @brief Definition for value of EVENT_KEY_HOUR_FORMAT.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_HOURFORMAT_24 "24"


/**
 * @brief Definition for system-event of setting : language setting.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_LANGUAGE_SET
 */
#define SYSTEM_EVENT_LANGUAGE_SET "tizen.system.event.language_set"


/**
 * @brief Definition for key of SYSTEM_EVENT_LANGUAGE_SET.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The value of this key is full name of locale, for example,
 *	        "ko_KR.UTF8" : in case of Korean language
 *	        "en_US.UTF8" : in case of USA language,
 *	        refer to linux locale info.
 */
#define EVENT_KEY_LANGUAGE_SET "language_set"


/**
 * @brief Definition for system-event of setting : region format.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_REGION_FORMAT
 */
#define SYSTEM_EVENT_REGION_FORMAT "tizen.system.event.region_format"


/**
 * @brief Definition for key of SYSTEM_EVENT_REGION_FORMAT.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The value of this key is full name of locale, for example,
 *	        "ko_KR.UTF8" : in case of Korean region format
 *	        "en_US.UTF8" : in case of USA region format,
 *	        refer to linux locale info.
 */
#define EVENT_KEY_REGION_FORMAT "region_format"


/**
 * @brief Definition for system-event of setting : silent_mode.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_SILENT_MODE
 */
#define SYSTEM_EVENT_SILENT_MODE "tizen.system.event.silent_mode"


/**
 * @brief Definition for key of SYSTEM_EVENT_SILENT_MODE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_SILENTMODE_ON
 * @see EVENT_VAL_SILENTMODE_OFF
 */
#define EVENT_KEY_SILENT_MODE "silent_mode"


/**
 * @brief Definition for value of EVENT_KEY_SILENT_MODE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_SILENTMODE_ON "on"


/**
 * @brief Definition for value of EVENT_KEY_SILENT_MODE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_SILENTMODE_OFF "off"


/**
 * @brief Definition for system-event of setting : state of vibration.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_VIBRATION_STATE
 */
#define SYSTEM_EVENT_VIBRATION_STATE "tizen.system.event.vibration_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_VIBRATION_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_VIBRATION_ON
 * @see EVENT_VAL_VIBRATION_OFF
 */
#define EVENT_KEY_VIBRATION_STATE "vibration_state"


/**
 * @brief Definition for value of EVENT_KEY_VIBRATION_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_VIBRATION_ON "on"


/**
 * @brief Definition for value of EVENT_KEY_VIBRATION_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_VIBRATION_OFF "off"


/**
 * @brief Definition for system-event of setting : state of screen's auto-rotation.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_SCREEN_AUTOROTATE_STATE
 */
#define SYSTEM_EVENT_SCREEN_AUTOROTATE_STATE "tizen.system.event.screen_autorotate_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_SCREEN_AUTOROTATE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_SCREEN_AUTOROTATE_ON
 * @see EVENT_VAL_SCREEN_AUTOROTATE_OFF
 */
#define EVENT_KEY_SCREEN_AUTOROTATE_STATE "screen_autorotate_state"


/**
 * @brief Definition for value of EVENT_KEY_SCREEN_AUTOROTATE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_SCREEN_AUTOROTATE_ON "on"


/**
 * @brief Definition for value of EVENT_KEY_SCREEN_AUTOROTATE_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_SCREEN_AUTOROTATE_OFF "off"


/**
 * @brief Definition for system-event of setting : state of mobile data.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_MOBILE_DATA_STATE
 */
#define SYSTEM_EVENT_MOBILE_DATA_STATE "tizen.system.event.mobile_data_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_MOBILE_DATA_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_MOBILE_DATA_OFF
 * @see EVENT_VAL_MOBILE_DATA_ON
 */
#define EVENT_KEY_MOBILE_DATA_STATE "mobile_data_state"


/**
 * @brief Definition for value of EVENT_KEY_MOBILE_DATA_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_MOBILE_DATA_OFF "off"


/**
 * @brief Definition for value of EVENT_KEY_MOBILE_DATA_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_MOBILE_DATA_ON "on"


/**
 * @brief Definition for system-event of setting : state of data roaming.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_DATA_ROAMING_STATE
 */
#define SYSTEM_EVENT_DATA_ROAMING_STATE "tizen.system.event.data_roaming_state"


/**
 * @brief Definition for key of SYSTEM_EVENT_DATA_ROAMING_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_VAL_DATA_ROAMING_OFF
 * @see EVENT_VAL_DATA_ROAMING_ON
 */
#define EVENT_KEY_DATA_ROAMING_STATE "data_roaming_state"


/**
 * @brief Definition for value of EVENT_KEY_DATA_ROAMING_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_DATA_ROAMING_OFF "off"


/**
 * @brief Definition for value of EVENT_KEY_DATA_ROAMING_STATE.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 */
#define EVENT_VAL_DATA_ROAMING_ON "on"


/**
 * @brief Definition for system-event of setting : font setting.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @see EVENT_KEY_FONT_SET
 */
#define SYSTEM_EVENT_FONT_SET "tizen.system.event.font_set"


/**
 * @brief Definition for key of SYSTEM_EVENT_FONT_SET.
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The value of this key is font name of string type by font-config.
 */
#define EVENT_KEY_FONT_SET "font_set"


/**
 * @brief Definition for system-event of network : status of network.
 * @since_tizen 3.0
 * @see EVENT_KEY_NETWORK_STATUS
 */
#define SYSTEM_EVENT_NETWORK_STATUS "tizen.system.event.network_status"


/**
 * @brief Definition for key of SYSTEM_EVENT_NETWORK_STATUS.
 * @since_tizen 3.0
 * @remarks The values of this event indicate the type of the current profile for data connection.
 * @see EVENT_VAL_NETWORK_DISCONNECTED
 * @see EVENT_VAL_NETWORK_WIFI
 * @see EVENT_VAL_NETWORK_CELLULAR
 * @see EVENT_VAL_NETWORK_ETHERNET
 * @see EVENT_VAL_NETWORK_BT
 * @see EVENT_VAL_NETWORK_NET_PROXY
 */
#define EVENT_KEY_NETWORK_STATUS "network_status"


/**
 * @brief Definition for value of EVENT_KEY_NETWORK_STATUS.
 * @since_tizen 3.0
 */
#define EVENT_VAL_NETWORK_DISCONNECTED "disconnected"


/**
 * @brief Definition for value of EVENT_KEY_NETWORK_STATUS.
 * @since_tizen 3.0
 */
#define EVENT_VAL_NETWORK_WIFI "wifi"


/**
 * @brief Definition for value of EVENT_KEY_NETWORK_STATUS.
 * @since_tizen 3.0
 */
#define EVENT_VAL_NETWORK_CELLULAR "cellular"


/**
 * @brief Definition for value of EVENT_KEY_NETWORK_STATUS.
 * @since_tizen 3.0
 */
#define EVENT_VAL_NETWORK_ETHERNET "ethernet"


/**
 * @brief Definition for value of EVENT_KEY_NETWORK_STATUS.
 * @since_tizen 3.0
 */
#define EVENT_VAL_NETWORK_BT "bt"


/**
 * @brief Definition for value of EVENT_KEY_NETWORK_STATUS.
 * @since_tizen 3.0
 */
#define EVENT_VAL_NETWORK_NET_PROXY "net_proxy"


/**
 * @brief Adds the event handler for receiving event-data of interested events.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks If you want to add the privileged event, you MUST declare right privilege first. Unless that, this function returns #EVENT_ERROR_PERMISSION_DENIED. The privileged events are commented on remarks of it's definitions.
 * @param[in] event_name The interested event name
 * @param[in] callback The event callback called when the event occurs
 * @param[in] user_data The user data for passing to callback
 * @param[out] event_handler The event handler
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #EVENT_ERROR_NONE Successful
 * @retval #EVENT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #EVENT_ERROR_PERMISSION_DENIED Permission denied
 * @retval #EVENT_ERROR_IO_ERROR Adding handler failed
 * @retval #EVENT_ERROR_OUT_OF_MEMORY Out of memory
 */
int event_add_event_handler(const char *event_name, event_cb callback, void *user_data, event_handler_h *event_handler);


/**
 * @brief Removes the registered event handler.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @param[in] event_handler The event handler
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #EVENT_ERROR_NONE Successful
 * @retval #EVENT_ERROR_INVALID_PARAMETER Invalid parameter
 */
int event_remove_event_handler(event_handler_h event_handler);


/**
 * @brief Sends the User-Event to receiver applications.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The format of User-Event's name MUST be "event.{sender's appid}.{user-defined name}", refer to 'The name-format of User-Event' section, If the event_name is invalid, the function returns #EVENT_ERROR_IO_ERROR.
 * @param[in] event_name The event's name to send
 * @param[in] event_data The event's data to send
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #EVENT_ERROR_NONE Successful
 * @retval #EVENT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #EVENT_ERROR_IO_ERROR Sending operation failed
 */
int event_publish_app_event(const char *event_name, bundle *event_data);


/**
 * @brief Sends the User-Event to trusted receiver-applications.
 *
 * @since_tizen @if MOBILE 2.4 @elseif WEARABLE 3.0 @endif
 * @remarks The application which has same certification with sender can receive the event.
 * @remarks The format of User-Event's name MUST be "event.{sender's appid}.{user-defined name}", refer to 'The name-format of User-Event' section,  If the event_name is invalid, the function returns #EVENT_ERROR_IO_ERROR.
 * @param[in] event_name The event's name to send
 * @param[in] event_data The event's data to send
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #EVENT_ERROR_NONE Successful
 * @retval #EVENT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #EVENT_ERROR_IO_ERROR Sending operation failed
 */
int event_publish_trusted_app_event(const char *event_name, bundle *event_data);


/**
 * @brief Keeps last User-Event data for receiver applications.
 *
 * @since_tizen 3.0
 * @remarks The receiver applications will receive this last event data after adding their new handlers via event_add_event_handler() API since the sender application called this API.
 * @remarks If a sender application sends same event via trusted API and non-trusted API, then a trusted receiver will get latest data regardless of trusted or non-trusted, but non-trusted receiver will get the last data only from non-trusted API.
 * @remarks The effect of this API continues during runtime. That means when the sender application process restarts, the sender application needs to call this api again to make the event to keep the last event.
 * @param[in] event_name The event's name to keep last event data
 * @return @c 0 on success,
 *         otherwise a negative error value
 * @retval #EVENT_ERROR_NONE Successful
 * @retval #EVENT_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #EVENT_ERROR_IO_ERROR Sending operation failed
 * @retval #EVENT_ERROR_OUT_OF_MEMORY Out of memory
 */
int event_keep_last_event_data(const char *event_name);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __TIZEN_APPFW_EVENT_H__ */

