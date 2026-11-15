<?php defined("SYSPATH") or die("No direct script access.");
/**
 * Gallery - a web based photo album viewer and editor
 * Copyright (C) 2000-2013 Bharat Mediratta
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA  02110-1301, USA.
 */
class server_add_Core {
  public static function check_config($paths=null) {
    $paths ??= unserialize(module::get_var("server_add", "authorized_paths"));
    if (empty($paths)) {
      site_status::warning(
        t("Server Add needs configuration. <a href=\"%url\">Configure it now!</a>",
          ["url" => html::mark_clean(url::site("admin/server_add"))]),
        "server_add_configuration");
    } else {
      site_status::clear("server_add_configuration");
    }
  }

  public static function is_valid_path($path) {
    if (!is_string($path) || !is_readable($path) || is_link($path)) {
      return false;
    }

    // Compare canonical paths so that ".." segments and symlinked parents can't escape an
    // authorized directory, and so "/srv/photos" doesn't also authorize "/srv/photos-private".
    $real_path = realpath($path);
    if ($real_path === false) {
      return false;
    }

    $authorized_paths = unserialize(module::get_var("server_add", "authorized_paths"));
    foreach (array_keys($authorized_paths) as $valid_path) {
      $real_valid_path = realpath($valid_path);
      if ($real_valid_path === false) {
        continue;
      }
      if ($real_path === $real_valid_path ||
          str_starts_with($real_path, rtrim($real_valid_path, "/") . "/")) {
        return true;
      }
    }

    return false;
  }
}
