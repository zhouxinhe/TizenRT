/*
 * Copyright (c) 2015 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#define AUL_DBUS_PATH				"/aul/dbus_handler"
#define AUL_DBUS_SIGNAL_INTERFACE		"org.tizen.aul.signal"
#define AUL_DBUS_APPDEAD_SIGNAL			"app_dead"
#define AUL_DBUS_APPLAUNCH_SIGNAL		"app_launch"
#define AUL_DBUS_HOMELAUNCH_SIGNAL		"home_launch"

#define AUL_APP_STATUS_DBUS_PATH		"/Org/Tizen/Aul/AppStatus"
#define AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE	"org.tizen.aul.AppStatus"
#define STATUS_FOREGROUND			"fg"
#define STATUS_BACKGROUND			"bg"
#define AUL_APP_STATUS_DBUS_LAUNCH_REQUEST	"AppLaunch"
#define AUL_APP_STATUS_DBUS_RESUME_REQUEST	"AppResume"
#define AUL_APP_STATUS_DBUS_TERMINATE_REQUEST	"AppTerminate"
#define AUL_APP_STATUS_DBUS_STATUS_CHANGE	"AppStatusChange"
#define AUL_APP_STATUS_DBUS_GROUP		"AppGroup"
#define AUL_APP_STATUS_DBUS_TERMINATED		"AppTerminated"

#define SYSTEM_PATH_CORE			"/Org/Tizen/System/DeviceD/Core"
#define SYSTEM_INTERFACE_CORE			"org.tizen.system.deviced.core"
#define SYSTEM_SIGNAL_BOOTING_DONE		"BootingDone"

#define SYSTEM_PATH_SYSNOTI			"/Org/Tizen/System/DeviceD/SysNoti"
#define SYSTEM_INTERFACE_SYSNOTI		"org.tizen.system.deviced.SysNoti"
#define SYSTEM_SIGNAL_COOLDOWN_CHANGED		"CoolDownChanged"

#define ROTATION_BUS_NAME			"org.tizen.system.coord"
#define ROTATION_OBJECT_PATH			"/Org/Tizen/System/Coord/Rotation"
#define ROTATION_INTERFACE_NAME			"org.tizen.system.coord.rotation"
#define ROTATION_METHOD_NAME			"Degree"

#define APPFW_SUSPEND_HINT_PATH			"/Org/Tizen/Appfw/SuspendHint"
#define APPFW_SUSPEND_HINT_INTERFACE		"org.tizen.appfw.SuspendHint"
#define APPFW_SUSPEND_HINT_SIGNAL		"SuspendHint"

#define RESOURCED_FREEZER_PATH			"/Org/Tizen/Resourced/Freezer"
#define RESOURCED_FREEZER_INTERFACE		"org.tizen.resourced.freezer"
#define RESOURCED_FREEZER_SIGNAL		"FreezerState"

#define RESOURCED_PROC_OBJECT			"/Org/Tizen/ResourceD/Process"
#define RESOURCED_PROC_INTERFACE		"org.tizen.resourced.process"
#define RESOURCED_PROC_METHOD			"ProcExclude"
#define RESOURCED_PROC_PRELAUNCH_SIGNAL		"ProcPrelaunch"
#define RESOURCED_PROC_WATCHDOG_SIGNAL		"ProcWatchdog"
#define RESOURCED_PROC_GROUP_SIGNAL		"ProcGroup"
#define RESOURCED_SYSTEM_SERVICE_SIGNAL		"SystemService"
#define RESOURCED_ALLOWED_BG_ATTRIBUTE		0x100
#define RESOURCED_BG_MANAGEMENT_ATTRIBUTE	0x200
#define RESOURCED_API_VER_2_4_ATTRIBUTE		0x400

#define PASS_BUS_NAME				"org.tizen.system.pass"
#define PASS_PATH_PMQOS				"/Org/Tizen/System/Pass/Pmqos"
#define PASS_INTERFACE_PMQOS			"org.tizen.system.pass.pmqos"
#define PASS_METHOD_APPLAUNCH			"AppLaunch"

#define SYSTEM_BUS_NAME				"org.tizen.system.deviced"
#define TEP_BUS_NAME				SYSTEM_BUS_NAME
#define TEP_OBJECT_PATH				"/Org/Tizen/System/DeviceD/Tzip"
#define TEP_INTERFACE_NAME			"org.tizen.system.deviced.Tzip"
#define TEP_MOUNT_METHOD			"Mount"
#define TEP_UNMOUNT_METHOD			"Unmount"
#define TEP_IS_MOUNTED_METHOD			"IsMounted"

#define WM_PROC_NAME				"org.enlightenment.wm"
#define WM_PROC_PATH				"/org/enlightenment/wm"
#define WM_PROC_INTERFACE			"org.enlightenment.wm.proc"
#define WM_PROC_METHOD				"GetProcStatus"

#define SD_BUS_NAME				"org.freedesktop.systemd1"
#define SD_OBJECT_PATH				"/org/freedesktop/systemd1"
#define SD_MANAGER_INTERFACE			"org.freedesktop.systemd1.Manager"
#define SD_STARTUP_FINISHED_SIGNAL		"StartupFinished"
#define SD_USER_SESSION_STARTUP_FINISHED_SIGNAL	"UserSessionStartupFinished"
#define SD_SUBSCRIBE_METHOD			"Subscribe"
#define SD_UNIT_OBJECT_PATH			"/org/freedesktop/systemd1/unit/default_2etarget"
#define SD_PROPERTIES_INTERFACE			"org.freedesktop.DBus.Properties"
#define SD_GET_METHOD				"Get"

#define SYSTEM_PATH_DISPLAY			"/Org/Tizen/System/DeviceD/Display"
#define SYSTEM_INTERFACE_DISPLAY		"org.tizen.system.deviced.display"
#define SYSTEM_LOCK_STATE			"lockstate"
#define SYSTEM_UNLOCK_STATE			"unlockstate"
#define SYSTEM_LCD_OFF				"lcdoff"
#define SYSTEM_STAY_CUR_STATE			"staycurstate"
#define SYSTEM_SLEEP_MARGIN			"sleepmargin"

#define SYSTEM_PATH_POWEROFF			"/Org/Tizen/System/DeviceD/PowerOff"
#define SYSTEM_INTERFACE_POWEROFF		"org.tizen.system.deviced.PowerOff"
#define SYSTEM_POWEROFF_STATE_SIGNAL		"ChangeState"
