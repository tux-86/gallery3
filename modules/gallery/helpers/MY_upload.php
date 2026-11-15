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
class upload extends upload_Core {
  /**
   * Like upload_Core::save(), but when the caller doesn't pick a name the file is stored under a
   * random server-chosen name instead of one derived from the client's file name.  The client's
   * extension is only kept if it is a legal photo/movie extension (the metadata code falls back
   * to it for some file types), so a temp file can never end up with e.g. a .php extension.
   */
  public static function save($file, $filename=null, $directory=null, $chmod=0644) {
    if ($filename === null) {
      $file = is_array($file) ? $file : $_FILES[$file];
      $extension = strtolower(pathinfo((string) ($file["name"] ?? ""), PATHINFO_EXTENSION));
      $filename = bin2hex(random_bytes(16));
      if ($extension !== "" && preg_match('/^[a-z0-9]{1,8}$/', $extension) &&
          legal_file::get_extensions($extension)) {
        $filename .= ".$extension";
      }
    }
    return parent::save($file, $filename, $directory, $chmod);
  }
}
