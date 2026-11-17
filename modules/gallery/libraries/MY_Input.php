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
class Input extends Input_Core {
  /**
   * The address of the client making this request.
   *
   * This is REMOTE_ADDR unless the request came through one of the reverse proxies listed in
   * config proxy.trusted_proxies, in which case it is the first address in the forwarding header
   * (read right to left) that isn't a trusted proxy.  Without trusted proxies configured the
   * forwarding headers are ignored entirely, since any visitor can send them.  IPv6 addresses
   * are returned in canonical form.  Returns 0.0.0.0 if no usable address can be determined.
   */
  public function ip_address() {
    if ($this->ip_address !== null) {
      return $this->ip_address;
    }

    $peer = self::_normalize_ip((string) $this->server("REMOTE_ADDR"));
    if ($peer === null) {
      return $this->ip_address = "0.0.0.0";
    }

    $trusted = (array) Kohana::config("proxy.trusted_proxies");
    $header = (string) Kohana::config("proxy.forwarded_header");
    $forwarded = ($trusted && $header !== "") ? (string) $this->server($header) : "";

    return $this->ip_address = self::resolve_client_ip($peer, $forwarded, $trusted);
  }

  /**
   * Work out the client address from the connecting peer and a forwarding header value.  Split
   * out from ip_address() so it can be tested without a request.
   *
   * @param  string $peer       the (valid, normalized) address that connected to us
   * @param  string $forwarded  the forwarding header's value ("" if absent)
   * @param  array  $trusted    trusted proxy addresses / CIDR ranges
   */
  public static function resolve_client_ip($peer, $forwarded, array $trusted) {
    if ($forwarded === "" || !self::ip_in_list($peer, $trusted)) {
      return $peer;
    }

    // Walk the chain from our side: each hop we trust vouches for the address to its left.  The
    // first address nobody vouches for is the client.  If an entry is garbage we can't tell
    // what happened to the left of it, so stop at the last hop we do know.
    $current = $peer;
    foreach (array_reverse(explode(",", $forwarded)) as $entry) {
      $ip = self::_normalize_ip(trim($entry));
      if ($ip === null) {
        return $current;
      }
      $current = $ip;
      if (!self::ip_in_list($ip, $trusted)) {
        return $ip;
      }
    }
    // Every hop was a trusted proxy; the left-most one is as far as we can see.
    return $current;
  }

  /**
   * Is this address in any of the given addresses / CIDR ranges?  Works for IPv4 and IPv6;
   * malformed list entries never match.
   */
  public static function ip_in_list($ip, array $list) {
    $packed = @inet_pton((string) $ip);
    if ($packed === false) {
      return false;
    }
    foreach ($list as $entry) {
      $parts = explode("/", trim((string) $entry), 2);
      $net = @inet_pton($parts[0]);
      if ($net === false || strlen($net) !== strlen($packed)) {
        continue;
      }
      $max = strlen($net) * 8;
      if (isset($parts[1])) {
        if (!ctype_digit($parts[1]) || (int) $parts[1] > $max) {
          continue;
        }
        $bits = (int) $parts[1];
      } else {
        $bits = $max;
      }

      $bytes = intdiv($bits, 8);
      if (substr($packed, 0, $bytes) !== substr($net, 0, $bytes)) {
        continue;
      }
      $rest = $bits % 8;
      if ($rest === 0) {
        return true;
      }
      $mask = (0xFF << (8 - $rest)) & 0xFF;
      if ((ord($packed[$bytes]) & $mask) === (ord($net[$bytes]) & $mask)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Validate an address (tolerating "[v6]:port", "v4:port" and IPv4-mapped IPv6 forms that
   * proxies emit) and return it in canonical form, or null if it isn't one.
   */
  private static function _normalize_ip($value) {
    $value = trim($value);
    if (preg_match('/^\[([0-9a-f:.]+)\](?::\d+)?$/i', $value, $m)) {
      $value = $m[1];
    } else if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', $value, $m)) {
      $value = $m[1];
    }
    $packed = filter_var($value, FILTER_VALIDATE_IP) ? @inet_pton($value) : false;
    if ($packed === false) {
      return null;
    }
    // ::ffff:1.2.3.4 is the same client as 1.2.3.4.
    if (strlen($packed) === 16 && str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
      $packed = substr($packed, 12);
    }
    return inet_ntop($packed);
  }

  /**
   * Group a client address with the others it is probably under the same control as: an IPv6
   * address is reduced to its /64 (a single subscriber commonly has billions of addresses in
   * one), an IPv4 address stands for itself.
   */
  public static function client_network($ip) {
    $packed = @inet_pton((string) $ip);
    if ($packed !== false && strlen($packed) === 16) {
      return inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . "/64";
    }
    return (string) $ip;
  }

  /**
   * Modified form of Input::clean_input_keys() that replaces malformed values
   * instead of dying on bad input.
   *
   * @param   string  string to clean
   * @return  string
   */
  public function clean_input_keys($str) {
    return preg_replace('#[^a-zA-Z0-9:_.-]+#', '_', $str);
  }
}
