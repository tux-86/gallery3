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
 * Reverse proxies / load balancers / CDNs in front of Gallery.
 *
 * By default Gallery treats the address that connected to the web server (REMOTE_ADDR) as the
 * client.  If Gallery runs behind a reverse proxy, that is the proxy's address for every
 * visitor, which makes per-client features such as the failed login lockout treat all visitors
 * as one client.
 *
 * To fix that, list the proxies you control in $config["trusted_proxies"].  Only when a request
 * arrives from one of them is the forwarding header consulted, and then only the entries a
 * trusted proxy could have added: the header is read from right to left and the first address
 * that is not itself a trusted proxy is the client.  Anything a visitor puts at the left of the
 * header is ignored.  Never list addresses you do not control, and make sure your proxy
 * overwrites or appends to (never blindly forwards) the header it receives.
 *
 * Don't edit this file.  Create var/proxy.php instead (it is included below), for example:
 *
 *   <?php
 *   $config["trusted_proxies"] = ["10.0.0.5", "192.168.1.0/24", "2001:db8::/32"];
 *
 * Entries are single IPv4/IPv6 addresses or CIDR ranges.
 */
$config["trusted_proxies"] = [];

/**
 * The $_SERVER key holding the forwarding header your proxy sets.  Use "HTTP_X_FORWARDED_FOR"
 * for the usual X-Forwarded-For (a comma separated list of addresses), or e.g.
 * "HTTP_X_REAL_IP" / "HTTP_CF_CONNECTING_IP" for proxies that set a single address.
 */
$config["forwarded_header"] = "HTTP_X_FORWARDED_FOR";

if (file_exists(VARPATH . "proxy.php")) {
  include(VARPATH . "proxy.php");
}
