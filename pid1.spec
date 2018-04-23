Name:           pid1
Version:        2.3
Release:        2%{?dist}
Summary:        Treadmill pid1 utility.

License:        Apache 2.0
URL:            https://github.com/Morgan-Stanley/treadmill-pid1 
Source0:        %{name}-%{version}.tar.gz 


%description
Treadmill pid1 utility.


%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/pid1
%doc


%changelog
* Tue Apr 17 2018 Andrei Keis andreikeis@noreply.github.com - 1.0-2
- Initial RPM release.

