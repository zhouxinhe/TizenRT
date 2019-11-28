Name:       amd
Summary:    Application Management Daemon
Version:    1.5.22
Release:    1
Group:      Application Framework/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source100:  ac.conf
Source101:  ac.service
Source102:  ac.socket
Source103:  amd.conf
Source1001: %{name}.manifest

Requires(post):   /sbin/ldconfig
Requires(post):   /usr/bin/systemctl
Requires(postun): /sbin/ldconfig
Requires(postun): /usr/bin/systemctl
Requires(preun):  /usr/bin/systemctl
Requires:   tizen-platform-config

BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(bundle)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(security-manager)
BuildRequires:  pkgconfig(rua)
BuildRequires:  pkgconfig(aul)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(pkgmgr-info)
BuildRequires:  pkgconfig(pkgmgr)
BuildRequires:  pkgconfig(libtzplatform-config)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(cynara-client-async)
BuildRequires:  pkgconfig(cynara-creds-socket)
BuildRequires:  pkgconfig(cynara-session)
BuildRequires:  pkgconfig(cert-svc-vcore)
BuildRequires:  pkgconfig(xkbcommon)
BuildRequires:  pkgconfig(sensor)
BuildRequires:  pkgconfig(ttrace)
BuildRequires:  pkgconfig(app2sd)
BuildRequires:  pkgconfig(wayland-client)
BuildRequires:  pkgconfig(tizen-extension-client)
BuildRequires:  pkgconfig(tizen-launch-client)
BuildRequires:  pkgconfig(wayland-tbm-client)
BuildRequires:  pkgconfig(capi-system-info)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  pkgconfig(iniparser)
BuildRequires:  pkgconfig(uuid)
BuildRequires:  pkgconfig(tanchor)

%description
Application management daemon

%package devel
Summary:    Application Management Daemon (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Application Management Daemon (devel)

%package -n amd-mod-launchpad
Summary:    AMD Module Launchpad
Group:      Application Framework/Service
Requires(post):  /usr/sbin/setcap
Requires(post):  /usr/bin/chsmack
Requires(postun):  /usr/sbin/setcap
Requires(postun):  /usr/bin/chsmack
Provides: app-launchpad

%description -n amd-mod-launchpad
AMD Module Launchpad

%package -n amd-mod-cooldown
Summary:    AMD module for supporting feature 'cool-down'
Group:      Application Framework/Service

%description -n amd-mod-cooldown
This module is for supporting feature 'cool-down'

%package -n amd-mod-wayland-core
Summary:    AMD module for connecting display server
Group:      Application Framework/Service

%description -n amd-mod-wayland-core
This module is for connecting display server

%package -n amd-mod-splash-screen
Summary:    AMD module for supporting feature 'splash-screen'
Group:      Application Framework/Service

%description -n amd-mod-splash-screen
This module is for supporting feature 'splash-screen'

%package -n amd-mod-input
Summary:    AMD module for controlling key and mouse events
Group:      Application Framework/Service

%description -n amd-mod-input
This module is for controlling key and mouse events

%package -n amd-mod-widget
Summary:    AMD module for widgets
Group:      Application Framework/Service

%description -n amd-mod-widget
This module is for supporting widgets

%package -n amd-mod-share
Summary:    AMD module for sharing application's private files
Group:      Application Framework/Service

%description -n amd-mod-share
This module is for supporting sharing of application's private files

%package -n amd-mod-ui-core
Summary:    AMD module for supporting UI related features
Group:      Application Framework/Service

%description -n amd-mod-ui-core
This module is for supporting UI related features such as 'app-group' and 'rua'

%package -n amd-mod-extractor
Summary:    AMD module for mounting and unmouting tizen package files
Group:      Application Framework/Service

%description -n amd-mod-extractor
This module is for mounting and unmouting tizen package files such as '.tep' and '.tpk'

%package -n amd-mod-cynara-core
Summary:    AMD module for access-control
Group:      Application Framework/Service

%description -n amd-mod-cynara-core
This module is for checking privileges

%package -n amd-mod-rua
Summary:    AMD module for managing recently-used-application
Group:      Application Framework/Service

%description -n amd-mod-rua
This module is for managing recently-used-application

%package -n amd-mod-watch
Summary:    AMD module for managing watch-application
Group:      Application Framework/Service

%description -n amd-mod-watch
This module is for managing watch-application

%package -n amd-mod-job-scheduler
Summary:    AMD module for supporting job-scheduler
Group:      Application Framework/Service

%description -n amd-mod-job-scheduler
This module is for supporting job-scheduler

%package -n amd-mod-boost
Summary:    AMD module for supporting cpu boost
Group:      Application Framework/Service

%description -n amd-mod-boost
This module is for supporting cpu boost

%package -n amd-mod-rpc-port
Summary:    AMD module for supporting rpc-port
Group:      Application Framework/Service

%description -n amd-mod-rpc-port
This module is for supporting rpc-port

%package -n amd-mod-complication
Summary:    AMD module for supporting complication
Group:      Application Framework/Service

%description -n amd-mod-complication
This module is for supporting complication

%package -n amd-mod-watchdog
Summary:    AMD module for supporting watchdog
Group:      Application Framework/Service

%description -n amd-mod-watchdog
This module is for supporting watchdog


%define _moddir %{_datadir}/amd

%prep
%setup -q
sed -i 's|TZ_SYS_DB|%{TZ_SYS_DB}|g' %{SOURCE1001}
cp %{SOURCE1001} .

%build
%if 0%{?simulator}
CFLAGS="%{optflags} -D__emul__"; export CFLAGS
%endif

%if 0%{?tizen_feature_terminate_unmanageable_app}
_TIZEN_FEATURE_TERMINATE_UNMANAGEABLE_APP=ON
%endif
%if 0%{?tizen_feature_block_input}
_TIZEN_FEATURE_BLOCK_INPUT=ON
%endif

MAJORVER=`echo %{version} | awk 'BEGIN {FS="."}{print $1}'`
%cmake -DFULLVER=%{version} \
	-DMAJORVER=${MAJORVER} \
	-DAMD_MODULES_DIR=%{_moddir} \
	.

%__make %{?_smp_mflags}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}%{_tmpfilesdir}
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}%{_unitdir}/sockets.target.wants
install -m 0644 %SOURCE100 %{buildroot}%{_tmpfilesdir}/ac.conf
install -m 0644 %SOURCE101 %{buildroot}%{_unitdir}/ac.service
install -m 0644 %SOURCE102 %{buildroot}%{_unitdir}/ac.socket
ln -sf ../ac.service %{buildroot}%{_unitdir}/multi-user.target.wants/ac.service
ln -sf ../ac.socket %{buildroot}%{_unitdir}/sockets.target.wants/ac.socket

mkdir -p %{buildroot}%{_datadir}/amd/conf
install -m 0644 %SOURCE103 %{buildroot}%{_datadir}/amd/conf/amd.conf

%preun
if [ $1 == 0 ]; then
    systemctl stop ac.service
    systemctl disable ac
fi

%post
/sbin/ldconfig

systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart ac.service
fi

%postun
/sbin/ldconfig
systemctl daemon-reload

%post -n amd-mod-launchpad
/sbin/ldconfig
/usr/bin/chsmack -e "System::Privileged" %{_bindir}/amd

%files
%license LICENSE
%manifest %{name}.manifest
%{_tmpfilesdir}/ac.conf
%{_unitdir}/ac.service
%{_unitdir}/multi-user.target.wants/ac.service
%{_unitdir}/ac.socket
%{_unitdir}/sockets.target.wants/ac.socket
%{_bindir}/amd
%{_libdir}/libamd.so.*
%{_moddir}/libamd.so
%{_moddir}/conf/amd.conf

%files devel
%{_includedir}/amd/*.h
%{_libdir}/libamd.so
%{_libdir}/pkgconfig/*pc

%files -n amd-mod-launchpad
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-launchpad.so

%files -n amd-mod-cooldown
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-cooldown.so

%files -n amd-mod-wayland-core
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-wayland-core.so

%files -n amd-mod-splash-screen
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-splash-screen.so

%files -n amd-mod-input
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-input.so
%{_moddir}/conf/amd_input.conf

%files -n amd-mod-widget
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-widget.so

%files -n amd-mod-share
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-share.so

%files -n amd-mod-ui-core
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-ui-core.so

%files -n amd-mod-extractor
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-extractor.so

%files -n amd-mod-cynara-core
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-cynara-core.so

%files -n amd-mod-rua
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-rua.so

%files -n amd-mod-watch
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-watch.so

%files -n amd-mod-job-scheduler
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-job-scheduler.so

%files -n amd-mod-boost
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-boost.so

%files -n amd-mod-rpc-port
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-rpc-port.so

%files -n amd-mod-complication
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-complication.so

%files -n amd-mod-watchdog
%manifest %{name}.manifest
%license LICENSE
%{_moddir}/mod/libamd-mod-watchdog.so
%{_moddir}/conf/amd_watchdog.conf
