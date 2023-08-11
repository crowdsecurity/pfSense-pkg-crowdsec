<?php
/*
 * crowdsec/status.php
 *
 * Copyright (c) 2020-2023 Crowdsec
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("guiconfig.inc");
require_once("globals.inc");


$g['disablehelpicon'] = true;

$pgtitle = array(gettext("Security"), gettext("CrowdSec"), gettext("Metrics"));
$pglinks = ['@self', '@self', '@self'];
$shortcut_section = "crowdsec";

include("head.inc");

$tab_array = array();
$tab_array[] = array("CrowdSec", false, "/crowdsec/landing.php");
$tab_array[] = array("Settings", false, "/pkg_edit.php?xml=crowdsec.xml&amp;id=0");
$tab_array[] = array("Status", false, "/crowdsec/status.php");
$tab_array[] = array("Metrics", true, "/crowdsec/metrics.php");
display_top_tabs($tab_array);

require('./metrics.html');

include("foot.inc");
