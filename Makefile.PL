use inc::Module::Install;

name     'RFID-Biblio';
all_from 'lib/RFID/Biblio.pm';
author   q{Dobrica Pavlinusic <dpavlin@rot13.org>};
license  'gpl';

requires 'Carp';
requires 'Data::Dump';
requires 'Device::SerialPort';
requires 'Time::HiRes';

build_requires 'Test::More';

build_requires 'Module::Install::Repository';
auto_set_repository;

test_requires 'Pod::Readme';

auto_install;

WriteAll;

