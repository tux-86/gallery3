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
/*
 * Based on the Cache_Sqlite_Driver developed by the Kohana Team
 */
class IdentityProvider_Gallery_Driver implements IdentityProvider_Driver {
  /**
   * @see IdentityProvider_Driver::guest.
   */
  public function guest() {
    return user::guest();
  }

  /**
   * @see IdentityProvider_Driver::guest.
   */
  public function admin_user() {
    return user::admin_user();
  }

  /**
   * @see IdentityProvider_Driver::create_user.
   */
  public function create_user($name, $full_name, $password, $email) {
    $user = ORM::factory("user");
    $user->name = $name;
    $user->full_name = $full_name;
    $user->password = $password;
    $user->email = $email;
    return $user->save();
  }

  /**
   * @see IdentityProvider_Driver::is_correct_password.
   */
  public function is_correct_password($user, $password) {
    // One implementation (bcrypt plus legacy hash support and upgrading) lives in the helper.
    return user::is_correct_password($user, $password);
  }

  /**
   * @see IdentityProvider_Driver::lookup_user.
   */
  public function lookup_user($id) {
    return user::lookup($id);
  }

  /**
   * @see IdentityProvider_Driver::lookup_user_by_name.
   */
  public function lookup_user_by_name($name) {
    return user::lookup_by_name($name);
  }

  /**
   * @see IdentityProvider_Driver::create_group.
   */
  public function create_group($name) {
    $group = ORM::factory("group");
    $group->name = $name;
    return $group->save();
  }

  /**
   * @see IdentityProvider_Driver::everybody.
   */
  public function everybody() {
    return group::everybody();
  }

  /**
   * @see IdentityProvider_Driver::registered_users.
   */
  public function registered_users() {
    return group::registered_users();
  }

  /**
   * @see IdentityProvider_Driver::lookup_group.
   */
  public function lookup_group($id) {
    return group::lookup($id);
  }

  /**
   * @see IdentityProvider_Driver::lookup_group_by_name.
   */
  public function lookup_group_by_name($name) {
    return group::lookup_by_name($name);
  }

  /**
   * @see IdentityProvider_Driver::get_user_list.
   */
  public function get_user_list($ids) {
    return ORM::factory("user")
      ->where("id", "IN", $ids)
      ->find_all();
  }

  /**
   * @see IdentityProvider_Driver::groups.
   */
  public function groups() {
    return ORM::factory("group")->find_all();
  }

  /**
   * @see IdentityProvider_Driver::add_user_to_group.
   */
  public function add_user_to_group($user, $group) {
    $group->add($user);
    $group->save();
  }

  /**
   * @see IdentityProvider_Driver::remove_user_to_group.
   */
  public function remove_user_from_group($user, $group) {
    $group->remove($user);
    $group->save();
  }
} // End Identity Gallery Driver

