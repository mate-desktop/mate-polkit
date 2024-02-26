project('mate-polkit', 'c',
  license : 'GPL2+',
  version : '1.28.1',
  meson_version : '>=0.43'
)

glib_version = '>=2.50'
gtk_version = '>=3.22'
agent_version = '>=0.97'
gobject_version = '>=0.97'

gnome = import('gnome')
i18n = import('i18n')
gettext_package = meson.project_name()
prefix = get_option('prefix')
datadir = join_paths(prefix, get_option('datadir'))
sysconfdir = join_paths(prefix, get_option('sysconfdir'))
libexecdir = join_paths(prefix, get_option('libexecdir'))
# Dependencies

glib_dep = dependency('glib-2.0', version : glib_version)
gthread_dep = dependency('gthread-2.0')
gtk_dep = dependency('gtk+-3.0', version : gtk_version)
agent_dep = dependency('polkit-agent-1', version : agent_version)
gobject_dep = dependency('polkit-gobject-1', version : gobject_version)

# Optional dependencies

if get_option('accountsservice')
  accountsservice_dep = dependency('accountsservice', required : false)
  build_accountsservice = accountsservice_dep.found()
else
  build_accountsservice = false
endif

appindicator_ayatana_dep = dependency('ayatana-appindicator3-0.1', required : false)
ubuntu_ayatana_dep = dependency('appindicator3-0.1', required : false)
appindicator_ayatana = appindicator_ayatana_dep.found()
ubuntu_ayatana = ubuntu_ayatana_dep.found()

if get_option('appindicator') == 'yes'
  if appindicator_ayatana
    appindicator_dep = dependency('ayatana-appindicator3-0.1')
  elif ubuntu_ayatana
    appindicator_dep = dependency('appindicator3-0.1')
  else
    error ('Neither Ayatana AppIndicator nor Ubuntu AppIndicator library is present, but you enabled AppIndicator support.')
  endif
elif get_option('appindicator') == 'auto'
  if appindicator_ayatana
    appindicator_dep = dependency('ayatana-appindicator3-0.1')
  elif ubuntu_ayatana
    appindicator_dep = dependency('appindicator3-0.1')
  else
    appindicator_dep = []
  endif
else
   appindicator_dep = []
endif

# config.h

config_data = configuration_data()
config_data.set_quoted('GETTEXT_PACKAGE', gettext_package)
config_data.set_quoted('MATELOCALEDIR', join_paths(prefix, get_option('localedir')))
config_data.set_quoted('PACKAGE_NAME', meson.project_name())
config_data.set_quoted('PACKAGE_VERSION', meson.project_version())
config_data.set_quoted('VERSION', meson.project_version())
config_data.set_quoted('PKG_DATA_DIR', join_paths(prefix, get_option('datadir'), meson.project_name()))
config_data.set_quoted('ENGRAMPA_RESOURCE_UI_PATH', '/org/mate/Engrampa/ui')
config_data.set_quoted('PACKAGE_URL', 'https://mate-desktop.org')
if build_accountsservice
  config_data.set('HAVE_ACCOUNTSSERVICE', 1)
endif
if appindicator_ayatana and get_option('appindicator') != 'no'
  config_data.set('HAVE_AYATANA_APPINDICATOR', 1)
elif ubuntu_ayatana and get_option('appindicator') != 'no'
  config_data.set('HAVE_UBUNTU_APPINDICATOR', 1)
endif
config_file = configure_file(output : 'config.h', configuration : config_data)
config_inc = include_directories('.')

# C args

c_args = [ 
  '-Wall',
  '-Wcast-align',
  '-Wtype-limits',
  '-Wclobbered',
  '-Wempty-body',
  '-Wignored-qualifiers',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wpointer-arith',
  '-Wno-sign-compare',
  '-Wformat-security',
  '-Wno-deprecated-declarations'
]

# Subdirectories

subdir('po')
subdir('src')

# Summary

summary = [
  'configuration summary:',
  '',
  '                         project: @0@ @1@'.format(meson.project_name(), meson.project_version()),
  '                          prefix: @0@'.format(prefix),
  '                      sysconfdir: @0@'.format(sysconfdir),
  '                 Accountsservice: @0@'.format(build_accountsservice),
  '                    AppIndicator: @0@'.format(get_option('appindicator')),
  'Ayatana AppIndicator (preferred): @0@'.format(appindicator_ayatana),
  'Ubuntu AppIndicator (legacy):     @0@'.format(ubuntu_ayatana),
  ''
]
message('\n'.join(summary))
