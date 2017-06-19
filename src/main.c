/*
 * Copyright (C) 2009 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>
#include <gtk/gtk.h>
#include <gio/gio.h>
#include <glib/gi18n.h>
#include <polkitagent/polkitagent.h>

#ifdef HAVE_APPINDICATOR
#include <libappindicator/app-indicator.h>
#endif

#include "polkitmatelistener.h"

/* session management support for auto-restart */
#define SM_DBUS_NAME      "org.mate.SessionManager"
#define SM_DBUS_PATH      "/org/mate/SessionManager"
#define SM_DBUS_INTERFACE "org.mate.SessionManager"
#define SM_CLIENT_DBUS_INTERFACE "org.mate.SessionManager.ClientPrivate"


/* the Authority */
static PolkitAuthority *authority = NULL;

/* the session we are servicing */
static PolkitSubject *session = NULL;

/* the current set of temporary authorizations */
static GList *current_temporary_authorizations = NULL;

#ifdef HAVE_APPINDICATOR
static AppIndicator *app_indicator = NULL;
#else
static GtkStatusIcon *status_icon = NULL;
#endif

static GDBusProxy      *sm_proxy;
static GDBusProxy      *client_proxy = NULL;

static  GMainLoop *loop;

static void
revoke_tmp_authz_cb (GObject      *source_object,
                     GAsyncResult *res,
                     gpointer      user_data)
{
  GError *error;

  error = NULL;
  polkit_authority_revoke_temporary_authorizations_finish (POLKIT_AUTHORITY (source_object),
                                                           res,
                                                           &error);
  if (error != NULL)
    {
      g_warning ("Error revoking temporary authorizations: %s", error->message);
      g_error_free (error);
    }
}

static void
revoke_tmp_authz (void)
{
  polkit_authority_revoke_temporary_authorizations (authority,
                                                    session,
                                                    NULL,
                                                    revoke_tmp_authz_cb,
                                                    NULL);
}

#ifdef HAVE_APPINDICATOR
static void
on_menu_item_activate (GtkMenuItem *menu_item,
                       gpointer     user_data)
{
  revoke_tmp_authz ();
}
#else
static void
on_status_icon_activate (GtkStatusIcon *status_icon,
                         gpointer       user_data)
{
  revoke_tmp_authz ();
}

static void
on_status_icon_popup_menu (GtkStatusIcon *status_icon,
                           guint          button,
                           guint          activate_time,
                           gpointer       user_data)
{
  revoke_tmp_authz ();
}
#endif

static void
update_temporary_authorization_icon_real (void)
{

#if 0
  GList *l;
  g_debug ("have %d tmp authorizations", g_list_length (current_temporary_authorizations));
  for (l = current_temporary_authorizations; l != NULL; l = l->next)
    {
      PolkitTemporaryAuthorization *authz = POLKIT_TEMPORARY_AUTHORIZATION (l->data);

      g_debug ("have tmp authz for action %s (subject %s) with id %s (obtained %d, expires %d)",
               polkit_temporary_authorization_get_action_id (authz),
               polkit_subject_to_string (polkit_temporary_authorization_get_subject (authz)),
               polkit_temporary_authorization_get_id (authz),
               (gint) polkit_temporary_authorization_get_time_obtained (authz),
               (gint) polkit_temporary_authorization_get_time_expires (authz));
    }
#endif

  /* TODO:
   *
   * - we could do something fancy like displaying a window with the tmp authz
   *   when the icon is clicked...
   *
   * - we could do some work using polkit_subject_exists() to ignore tmp authz
   *   for subjects that no longer exists.. this is because temporary authorizations
   *   are only valid for the subject that trigger the authentication dialog.
   *
   *   Maybe the authority could do this, would probably involve some polling, but
   *   it seems cleaner to do this server side.
   */

  if (current_temporary_authorizations != NULL)
    {
      /* show icon */
#ifdef HAVE_APPINDICATOR
      if (app_indicator == NULL)
        {
          GtkWidget *item, *menu;

          app_indicator = app_indicator_new ("mate-polkit",
                                             "dialog-password",
                                             APP_INDICATOR_CATEGORY_SYSTEM_SERVICES);

          item = gtk_menu_item_new_with_label (_("Drop all elevated privileges"));
          g_signal_connect (item,
                            "activate",
                            G_CALLBACK (on_menu_item_activate),
                            NULL);
          menu = gtk_menu_new ();
          gtk_menu_shell_append (GTK_MENU_SHELL (menu), item);
          gtk_widget_show_all (menu);

          app_indicator_set_menu (app_indicator,
                                  GTK_MENU (menu));
          app_indicator_set_status (app_indicator,
                                    APP_INDICATOR_STATUS_ACTIVE);
        }

#else
      if (status_icon == NULL)
        {
          status_icon = gtk_status_icon_new_from_icon_name ("dialog-password");
          gtk_status_icon_set_tooltip_text (status_icon,
                                            _("Click the icon to drop all elevated privileges"));
          g_signal_connect (status_icon,
                            "activate",
                            G_CALLBACK (on_status_icon_activate),
                            NULL);
          g_signal_connect (status_icon,
                            "popup-menu",
                            G_CALLBACK (on_status_icon_popup_menu),
                            NULL);
        }
#endif
    }
  else
    {
      /* hide icon */
#ifdef HAVE_APPINDICATOR
      if (app_indicator != NULL)
        {
          app_indicator_set_status (app_indicator,
				    APP_INDICATOR_STATUS_PASSIVE);
          g_object_unref (app_indicator);
          app_indicator = NULL;
        }
#else
      if (status_icon != NULL)
        {
          gtk_status_icon_set_visible (status_icon, FALSE);
          g_object_unref (status_icon);
          status_icon = NULL;
        }
#endif
    }
}

static void
enumerate_temporary_authorizations_cb (GObject      *source_object,
                                       GAsyncResult *res,
                                       gpointer      user_data)
{
  PolkitAuthority *authority = POLKIT_AUTHORITY (source_object);
  GList *temporary_authorizations;
  GError *error;

  temporary_authorizations = NULL;

  error = NULL;
  temporary_authorizations = polkit_authority_enumerate_temporary_authorizations_finish (authority,
                                                                                         res,
                                                                                         &error);
  if (error != NULL)
    {
      g_warning ("Error enumerating temporary authorizations: %s", error->message);
      g_error_free (error);
      goto out;
    }

  g_list_foreach (current_temporary_authorizations, (GFunc) g_object_unref, NULL);
  g_list_free (current_temporary_authorizations);

  current_temporary_authorizations = temporary_authorizations;

  update_temporary_authorization_icon_real ();

 out:
  ;
}

static void
update_temporary_authorization_icon (PolkitAuthority *authority)
{
  polkit_authority_enumerate_temporary_authorizations (authority,
                                                       session,
                                                       NULL,
                                                       enumerate_temporary_authorizations_cb,
                                                       NULL);
}

static void
on_authority_changed (PolkitAuthority *authority,
                      gpointer         user_data)
{
  update_temporary_authorization_icon (authority);
}

static void
stop_cb (void)
{
        g_main_loop_quit (loop);
}

static gboolean
end_session_response (gboolean is_okay, const gchar *reason)
{
        GVariant *res;
        GError *error = NULL;

        res = g_dbus_proxy_call_sync (client_proxy,
                                      "EndSessionResponse",
                                      g_variant_new ("(bs)",
                                                     is_okay,
                                                     reason),
                                      G_DBUS_CALL_FLAGS_NONE,
                                      -1, /* timeout */
                                      NULL, /* GCancellable */
                                      &error);
        if (! res) {
                g_warning ("Failed to call EndSessionResponse: %s", error->message);
                g_error_free (error);
                return FALSE;
        }

        g_variant_unref (res);
        return TRUE;
}

static void
query_end_session_cb (void)
{
        end_session_response (TRUE, "");
}

static void
end_session_cb (void)
{
        end_session_response (TRUE, "");
        g_main_loop_quit (loop);
}

static void
signal_cb (GDBusProxy *proxy, gchar *sender_name, gchar *signal_name,
           GVariant *parameters, gpointer user_data)
{
        if (strcmp (signal_name, "Stop") == 0) {
                stop_cb ();
        } else if (strcmp (signal_name, "QueryEndSession") == 0) {
                query_end_session_cb ();
        } else if (strcmp (signal_name, "EndSession") == 0) {
                end_session_cb ();
        }
}

static gboolean
register_client_to_mate_session (void)
{
        GError     *error = NULL;
        GVariant   *res;
        const char *startup_id;
        const char *app_id;
        char       *client_id;

        startup_id = g_getenv ("DESKTOP_AUTOSTART_ID");
        app_id = "polkit-mate-authentication-agent-1.desktop";

        sm_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SESSION,
                                                  G_DBUS_PROXY_FLAGS_NONE,
                                                  NULL, /* GDBusInterfaceInfo */
                                                  SM_DBUS_NAME,
                                                  SM_DBUS_PATH,
                                                  SM_DBUS_INTERFACE,
                                                  NULL, /* GCancellable */
                                                  &error);
        if (sm_proxy == NULL) {
                g_message("Failed to get session manager: %s", error->message);
                g_error_free (error);
                return FALSE;
        }

        res = g_dbus_proxy_call_sync (sm_proxy,
                                      "RegisterClient",
                                      g_variant_new ("(ss)",
                                                     app_id,
                                                     startup_id),
                                      G_DBUS_CALL_FLAGS_NONE,
                                      -1, /* timeout */
                                      NULL, /* GCancellable */
                                      &error);
        if (! res) {
                g_warning ("Failed to register client: %s", error->message);
                g_error_free (error);
                return FALSE;
        }

        if (! g_variant_is_of_type (res, G_VARIANT_TYPE ("(o)"))) {
                g_warning ("RegisterClient returned unexpected type %s",
                           g_variant_get_type_string (res));
                return FALSE;
        }

        g_variant_get (res, "(&o)", &client_id);

        client_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SESSION,
                                                      G_DBUS_PROXY_FLAGS_NONE,
                                                      NULL, /* GDBusInterfaceInfo */
                                                      SM_DBUS_NAME,
                                                      client_id,
                                                      SM_CLIENT_DBUS_INTERFACE,
                                                      NULL, /* GCancellable */
                                                      &error);
        g_variant_unref (res);
        if (client_proxy == NULL) {
                g_message("Failed to get client proxy: %s", error->message);
                g_error_free (error);
                return FALSE;
        }

        g_signal_connect (client_proxy, "g-signal", G_CALLBACK (signal_cb), NULL);

        return TRUE;
}

int
main (int argc, char **argv)
{
  gint ret;
  PolkitAgentListener *listener;
  GError *error;

  gtk_init (&argc, &argv);

  loop = NULL;
  authority = NULL;
  listener = NULL;
  session = NULL;
  ret = 1;

  bindtextdomain (GETTEXT_PACKAGE, MATELOCALEDIR);
#if HAVE_BIND_TEXTDOMAIN_CODESET
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
#endif
  textdomain (GETTEXT_PACKAGE);

  loop = g_main_loop_new (NULL, FALSE);

  error = NULL;
  authority = polkit_authority_get_sync (NULL /* GCancellable* */, &error);
  if (authority == NULL)
    {
      g_warning ("Error getting authority: %s", error->message);
      g_error_free (error);
      goto out;
    }
  g_signal_connect (authority,
                    "changed",
                    G_CALLBACK (on_authority_changed),
                    NULL);

  listener = polkit_mate_listener_new ();

  error = NULL;
  session = polkit_unix_session_new_for_process_sync (getpid (), NULL, &error);
  if (error != NULL)
    {
      g_warning ("Unable to determine the session we are in: %s", error->message);
      g_error_free (error);
      goto out;
    }

  error = NULL;
  if (!polkit_agent_listener_register (listener,
				       POLKIT_AGENT_REGISTER_FLAGS_NONE,
                                       session,
                                       "/org/mate/PolicyKit1/AuthenticationAgent",
				       NULL,
                                       &error))
    {
      g_printerr ("Cannot register authentication agent: %s\n", error->message);
      g_error_free (error);
      goto out;
    }

  update_temporary_authorization_icon (authority);

  register_client_to_mate_session();

  g_main_loop_run (loop);

  ret = 0;

 out:
  if (authority != NULL)
    g_object_unref (authority);
  if (session != NULL)
    g_object_unref (session);
  if (listener != NULL)
    g_object_unref (listener);
  if (loop != NULL)
    g_main_loop_unref (loop);

  return ret;
}
