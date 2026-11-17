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
class auth_Core {
  public static function get_login_form($url) {
    $form = new Forge($url, "", "post", ["id" => "g-login-form"]);
    $form->set_attr("class", "g-narrow");
    $form->hidden("continue_url")->value(Session::instance()->get("continue_url"));
    $group = $form->group("login")->label(t("Login"));
    $group->input("name")->label(t("Username"))->id("g-username")->class(null)
      ->callback("auth::validate_too_many_failed_logins")
      ->error_messages(
        "too_many_failed_logins", t("Too many failed login attempts.  Try again later"));
    $group->password("password")->label(t("Password"))->id("g-password")->class(null);
    $group->inputs["name"]->error_messages("invalid_login", t("Invalid name or password"));
    $group->submit("")->value(t("Login"));
    return $form;
  }

  public static function login($user) {
    identity::set_active_user($user);
    if (identity::is_writable()) {
      $user->login_count += 1;
      $user->last_login = time();
      $user->save();
    }
    log::info("user", t("User %name logged in", ["name" => $user->name]));
    module::event("user_login", $user);
  }

  public static function logout() {
    $user = identity::active_user();
    if (!$user->guest) {
      try {
        Session::instance()->destroy();
      } catch (Exception $e) {
        Kohana_Log::add("error", $e);
      }
      module::event("user_logout", $user);
    }
    log::info("user", t("User %name logged out", ["name" => $user->name]),
              t('<a href="%url">%user_name</a>',
                ["url" => user_profile::url($user->id),
                      "user_name" => html::clean($user->name)]));
  }

  // Failed authentications are counted per (user, client address) so that one person hammering
  // an account can't lock the real owner out, and per user from anywhere as a higher backstop
  // against attacks spread over many addresses.  Once a counter passes its threshold, any
  // failure within LOCKOUT_SECONDS of the last one keeps the lock going.  Counters that haven't
  // been touched for FAILURE_DECAY_SECONDS start over.
  const LOCKOUT_THRESHOLD = 5;
  const LOCKOUT_THRESHOLD_ANY_ADDRESS = 30;
  const LOCKOUT_SECONDS = 60;
  const FAILURE_DECAY_SECONDS = 900;

  /**
   * Has this user (or this client address, for this user) had too many failed auth attempts?
   */
  public static function too_many_failures($name) {
    foreach (self::_failure_counters(self::_failure_subject($name)) as $key => $threshold) {
      $failed = ORM::factory("failed_auth")->where("name", "=", $key)->find();
      if ($failed->loaded() &&
          $failed->count > $threshold &&
          (time() - $failed->time < self::LOCKOUT_SECONDS)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Identify who a login attempt is against.  Existing users are identified by id, so that
   * differently cased or accented spellings of a name (which the database treats as the same
   * user) can't be used to dodge the counters.  Unknown names are counted too, normalized.
   */
  private static function _failure_subject($name) {
    $name = (string) $name;
    $user = identity::lookup_user_by_name($name);
    if ($user) {
      return "id:" . $user->id;
    }
    return "name:" . mb_strtolower(trim($name));
  }

  /**
   * The counters (failed_auths.name values) that apply to this subject for the current client,
   * mapped to the threshold at which each one locks.
   */
  private static function _failure_counters($subject) {
    // Input::ip_address() is REMOTE_ADDR unless the request came through a reverse proxy the
    // admin has listed as trusted (see config/proxy.php), because forwarding headers are client
    // controlled and trusting them blindly would let an attacker pick a fresh "address" for
    // every guess.  IPv6 clients are grouped by /64 for the same reason.
    $address = Input::client_network(Input::instance()->ip_address());
    return [
      "n:" . hash("sha256", $subject . "\0" . $address) => self::LOCKOUT_THRESHOLD,
      "u:" . hash("sha256", $subject) => self::LOCKOUT_THRESHOLD_ANY_ADDRESS];
  }

  public static function validate_too_many_failed_logins($name_input) {
    if (auth::too_many_failures($name_input->value)) {
      $name_input->add_error("too_many_failed_logins", 1);
    }
  }

  public static function validate_too_many_failed_auth_attempts($form_input) {
    if (auth::too_many_failures(identity::active_user()->name)) {
      $form_input->add_error("too_many_failed_auth_attempts", 1);
    }
  }

  /**
   * Record a failed authentication for this user
   */
  public static function record_failed_attempt($name) {
    // Counters are per user and address, so unattended rows would otherwise pile up forever.
    // Expired ones are equivalent to no row at all, so prune them now and then.
    if (mt_rand(1, 20) === 1) {
      ORM::factory("failed_auth")
        ->where("time", "<", time() - self::FAILURE_DECAY_SECONDS)
        ->delete_all();
    }

    foreach (array_keys(self::_failure_counters(self::_failure_subject($name))) as $key) {
      $failed = ORM::factory("failed_auth")->where("name", "=", $key)->find();
      if (!$failed->loaded()) {
        $failed->name = $key;
      } else if (time() - $failed->time > self::FAILURE_DECAY_SECONDS) {
        $failed->count = 0;
      }
      $failed->time = time();
      $failed->count++;
      $failed->save();
    }
  }

  /**
   * Clear the failed logins for this user from this client address.  The user-wide counter is
   * left to expire on its own so that someone else guessing from elsewhere can't have it wiped
   * by the real user logging in.
   */
  public static function clear_failed_attempts($user) {
    $counters = array_keys(self::_failure_counters("id:" . $user->id));
    ORM::factory("failed_auth")
      ->where("name", "=", $counters[0])
      ->delete_all();
  }

  /**
   * Checks whether the current user (= admin) must
   * actively re-authenticate before access is given
   * to the admin area.
   */
  public static function must_reauth_for_admin_area() {
    if (!identity::active_user()->admin) {
      access::forbidden();
    }

    $session = Session::instance();
    $last_active_auth = $session->get("active_auth_timestamp", 0);
    $last_admin_area_activity = $session->get("admin_area_activity_timestamp", 0);
    $admin_area_timeout = module::get_var("gallery", "admin_area_timeout");

    if (max($last_active_auth, $last_admin_area_activity) + $admin_area_timeout < time()) {
      return true;
    }

    $session->set("admin_area_activity_timestamp", time());
    return false;
  }
}