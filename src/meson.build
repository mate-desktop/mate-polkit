po_dir = join_paths(meson.source_root(), 'po')
# Sources

source_files = files(
  'main.c',
  'polkitmateauthenticationdialog.c',
  'polkitmateauthenticator.c',
  'polkitmatelistener.c'

)

# Build targets

executable('polkit-mate-authentication-agent-1',
  sources : [
    config_file,
    source_files
  ],
  dependencies : [
    glib_dep,
    gthread_dep,
    gtk_dep,
    agent_dep,
    gobject_dep,
    appindicator_dep
  ],
  include_directories : config_inc,
  c_args : c_args + ['-DPOLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE'] + ['-DHAVE_CONFIG_H'],
  install : true,
  install_dir: get_option('libexecdir')
)

# .desktop file

desktop_data = configuration_data()
desktop_data.set('FULL_LIBEXECDIR', get_option('libexecdir'))
desktop_in_file = configure_file(
  input : 'polkit-mate-authentication-agent-1.desktop.in.in',
  output : 'polkit-mate-authentication-agent-1.desktop.in',
  configuration : desktop_data
)

i18n.merge_file(
  input : desktop_in_file,
  output : 'polkit-mate-authentication-agent-1.desktop',
  type : 'desktop',
  po_dir : po_dir,
  install : true,
  install_dir: join_paths(get_option('sysconfdir'), 'xdg', 'autostart')
)
