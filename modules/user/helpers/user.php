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

/**
 * This is the API for handling users.
 *
 * Note: by design, this class does not do any permission checking.
 */
class user_Core {
  // bcrypt work factor for newly stored passwords.
  const BCRYPT_COST = 12;
  // How long an emailed password reset link stays valid, and the minimum gap between two
  // reset emails for the same user (both in seconds).
  const RESET_TOKEN_TTL = 3600;
  const RESET_THROTTLE = 60;

  /**
   * Return the guest user.
   *
   * @todo consider caching
   *
   * @return User_Model
   */
  public static function guest() {
    return model_cache::get("user", 1);
  }

  /**
   * Return an admin user.  Prefer the currently logged in user, if possible.
   *
   * @return User_Model
   */
  public static function admin_user() {
    $active = identity::active_user();
    if ($active->admin) {
      return $active;
    }

    return ORM::factory("user")->where("admin", "=", 1)->order_by("id", "ASC")->find();
  }

  /**
   * Is the password provided correct?
   *
   * @param user User Model
   * @param string $password a plaintext password
   * @return boolean true if the password is correct
   */
  public static function is_correct_password($user, $password) {
    $valid = (string) $user->password;
    $password = (string) $password;

    // Accounts without a password (e.g. the guest user) can never log in with one.
    if ($valid === "") {
      return false;
    }

    // Current scheme: bcrypt.
    if (str_starts_with($valid, '$2y$')) {
      if (!password_verify(self::_prepare_password($password), $valid)) {
        return false;
      }
      if (password_needs_rehash($valid, PASSWORD_BCRYPT, ["cost" => self::BCRYPT_COST])) {
        self::_upgrade_hash($user, $password);
      }
      return true;
    }

    // Legacy schemes are still accepted so existing accounts keep working, but a successful
    // login immediately replaces the stored hash with a bcrypt one.
    $correct = false;
    if (strlen($valid) == 34) {
      // phpass (portable, iterated MD5), what earlier versions of this code generated.
      require_once(MODPATH . "user/lib/PasswordHash.php");
      $hashGenerator = new PasswordHash(10, true);
      $correct = $hashGenerator->CheckPassword($password, $valid);
    } else {
      $salt = substr($valid, 0, 4);
      // Support both old (G1 thru 1.4.0; G2 thru alpha-4) and new password schemes:
      $guess = (strlen($valid) == 32) ? md5($password) : ($salt . md5($salt . $password));
      if (hash_equals($valid, $guess)) {
        $correct = true;
      } else {
        // Passwords with <&"> created by G2 prior to 2.1 were hashed with entities
        $sanitizedPassword = html::chars($password, false);
        $guess = (strlen($valid) == 32) ? md5($sanitizedPassword)
              : ($salt . md5($salt . $sanitizedPassword));
        $correct = hash_equals($valid, $guess);
      }
    }

    if ($correct) {
      self::_upgrade_hash($user, $password);
    }
    return $correct;
  }

  /**
   * Replace a user's stored password hash with a fresh bcrypt hash of the (already verified)
   * password.  This writes straight to the database instead of calling $user->save() so that
   * logging in doesn't fire user update events.  A failure here must never break a login.
   */
  private static function _upgrade_hash($user, $password) {
    if (empty($user->id) || !empty($user->guest)) {
      return;
    }
    try {
      db::build()
        ->update("users")
        ->set(["password" => self::hash_password($password)])
        ->where("id", "=", $user->id)
        ->execute();
    } catch (Exception $e) {
      Kohana_Log::add("error", "Unable to upgrade password hash for user $user->id: " .
                      $e->getMessage());
    }
  }

  /**
   * bcrypt only looks at the first 72 bytes and chokes on NUL bytes, so longer or binary-ish
   * passwords are first reduced to a fixed-length digest.  Normal passwords pass through
   * untouched.
   */
  private static function _prepare_password($password) {
    if (strlen($password) > 72 || str_contains($password, "\0")) {
      return base64_encode(hash("sha256", $password, true));
    }
    return $password;
  }

  public static function valid_password($password_input) {
    if (!user::is_correct_password(identity::active_user(), $password_input->value)) {
      $password_input->add_error("invalid_password", 1);
    }
  }

  public static function valid_username($text_input) {
    if (!self::lookup_by_name($text_input->value)) {
      $text_input->add_error("invalid_username", 1);
    }
  }

  /**
   * Create the hashed passwords.
   * @param string $password a plaintext password
   * @return string hashed password
   */
  public static function hash_password($password) {
    return password_hash(
      self::_prepare_password((string) $password), PASSWORD_BCRYPT, ["cost" => self::BCRYPT_COST]);
  }

  /**
   * Password reset tokens.  The emailed token is random and single use; only a hash of it is
   * stored (in users.hash, so no schema change is needed) and the expiry lives in a module var.
   * Returns the plaintext token to email, or null if a reset was requested for this user so
   * recently that we should not send another one yet.
   */
  public static function create_reset_token($user) {
    $expires = (int) module::get_var("user", "reset_expires_{$user->id}", 0);
    $issued = $expires - self::RESET_TOKEN_TTL;
    if ($expires && time() - $issued < self::RESET_THROTTLE) {
      return null;
    }

    $token = random::hash();
    $user->hash = self::hash_reset_token($token);
    $user->save();
    module::set_var("user", "reset_expires_{$user->id}", time() + self::RESET_TOKEN_TTL);
    return $token;
  }

  /**
   * Find the user a (plaintext) reset token was issued to, or null if it is malformed, unknown
   * or expired.
   */
  public static function lookup_by_reset_token($token) {
    if (!is_string($token) || !preg_match('/^[0-9a-f]{32}$/', $token)) {
      return null;
    }
    $user = self::lookup_by_hash(self::hash_reset_token($token));
    if (empty($user)) {
      return null;
    }
    if ((int) module::get_var("user", "reset_expires_{$user->id}", 0) < time()) {
      return null;
    }
    return $user;
  }

  /**
   * Invalidate any outstanding reset token.  Does not save the user.
   */
  public static function clear_reset_token($user) {
    $user->hash = null;
    module::clear_var("user", "reset_expires_{$user->id}");
  }

  /**
   * One-way transform applied to a reset token before it is stored or looked up.  The token is
   * already 128 random bits, so a truncated SHA-256 (to fit char(32)) is plenty.
   */
  public static function hash_reset_token($token) {
    return substr(hash("sha256", (string) $token), 0, 32);
  }

  /**
   * Look up a user by id.
   * @param integer      $id the user id
   * @return User_Model  the user object, or null if the id was invalid.
   */
  public static function lookup($id) {
    return self::_lookup_user_by_field("id", $id);
  }

  /**
   * Look up a user by name.
   * @param integer      $name the user name
   * @return User_Model  the user object, or null if the name was invalid.
   */
  public static function lookup_by_name($name) {
    return self::_lookup_user_by_field("name", $name);
  }

  /**
   * Look up a user by hash.
   * @param integer      $hash the user hash value
   * @return User_Model  the user object, or null if the name was invalid.
   */
  public static function lookup_by_hash($hash) {
    return self::_lookup_user_by_field("hash", $hash);
  }

  /**
   * List the users
   * @param mixed      filters (@see Database.php
   * @return array     the user list.
   */
  public static function get_user_list($filter=[]) {
    $user = ORM::factory("user");

    foreach($filter as $method => $args) {
      match ($method) {
          "in" => $user->in($args[0], $args[1]),
          default => $user->$method($args),
      };
    }
    return $user->find_all();
  }

  /**
   * Look up a user by field value.
   * @param string      search field
   * @param string      search value
   * @return User_Core  the user object, or null if the name was invalid.
   */
  private static function _lookup_user_by_field($field_name, $value) {
    try {
      $user = model_cache::get("user", $value, $field_name);
      if ($user->loaded()) {
        return $user;
      }
    } catch (Exception $e) {
      if (!str_contains($e->getMessage(), "MISSING_MODEL")) {
       throw $e;
      }
    }
    return null;
  }
}