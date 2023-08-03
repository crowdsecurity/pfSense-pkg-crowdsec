<?php
/*
 * crowdsec_landing.php
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

$pgtitle = array(gettext("Security"), gettext("CrowdSec"));
$pglinks = ['@self', '@self', '@self'];
$shortcut_section = "crowdsec";

include("head.inc");

$tab_array = array();
$tab_array[] = array("Read me", true, "/crowdsec_landing.php");
$tab_array[] = array("Settings", false, "/pkg_edit.php?xml=crowdsec.xml&amp;id=0");
$tab_array[] = array("Status", false, "/crowdsec_status.php");
$tab_array[] = array("Metrics", false, "/crowdsec_metrics.php");
display_top_tabs($tab_array);


$content = <<<EOT
	<style type="text/css">
#introduction a.btn-info {
  color: black;
  margin: 3px;
}

.tab-pane {
  margin: 10px;
}
</style>


<div class="content-box tab-content">
    <div id="introduction" class="tab-pane fade in active">
        <h2>Quick Start</h2>

        <p>
            Go to the <a href="pkg_edit.php?xml=crowdsec.xml">Settings</a> tab and enable <b>Log Processor</b> and <b>Firewall Bouncer</b>. Click Save.
        </p>

        <p>
            Do not use the commands "sysrc" or "service" to enable and start the crowdsec or bouncer
            services, it is not required with pfSense. Do not create a <code>pf.conf</code> file.
            If you edit the configuration files, some setting may be overwritten by the pfsense package.
        </p>

        <p>
            CrowdSec on pfSense is fully functional from the command line but the web interface
            is read-only, with the exception of decision revocation (unban).
            Most actions require the shell or the <a href="https://app.crowdsec.net">CrowdSec Console</a>.
            For simple things, <a href="diag_command.php">Diagnostics/Command Prompt</a> works as well as ssh.
        </p>

        <h2>Walkthrough</h2>

        <p>If you are reading this, a CrowdSec <a href="https://doc.crowdsec.net/docs/next/getting_started/security_engine_intro">Security Engine</a>
        (threat detection) and a <a href="https://docs.crowdsec.net/docs/bouncers/firewall/">Firewall Bouncer</a> (remediation) are already installed
        in your pfSense machine.</p>

        The following protections are enabled by default on all interfaces:

        <ul>
            <li>portscan</li>
            <li>ssh brute-force</li>
            <li>pfSense admin brute-force</li>
        </ul>

        These scenarios will trigger a ban on the attacking IP (4 hours by default) and report it to the CrowdSec Central API
        (meaning <a href="https://docs.crowdsec.net/docs/concepts/">timestamp, scenario, attacking IP</a>), contributing to the
        Community Blocklist.</p>

        <p>You can add scenarios to detect other types of attack on the pfSense server, or
        <a href="https://doc.crowdsec.net/docs/next/user_guides/multiserver_setup">any other log processor</a>
        connected to the same LAPI node. Other types of remediation are possible (ex. captcha test for scraping attempts).</p>

        <p>
            We recommend you to <a href="https://app.crowdsec.net/">register to the Console</a>. This helps you manage your instances,
            and us to have better overall metrics.
        </p>

        <p>Please refer to the <a href="https://crowdsec.net/blog/category/tutorial/">tutorials</a> to explore
        the possibilities.</p>

        <div>
            <a class="btn btn-default btn-info" href="https://doc.crowdsec.net/docs/intro">
                Documentation
            </a>
            <a class="btn btn-default btn-info" href="https://crowdsec.net/blog/">
                Blog
            </a>
            <a class="btn btn-default btn-info" href="https://app.crowdsec.net/">
                Console
            </a>
            <a class="btn btn-default btn-info" href="https://hub.crowdsec.net/">
                CrowdSec Hub
            </a>
        </div>

        <h3>Status page</h3>

        <p>In the <a href="crowdsec_status.php">Status</a> tab, you can see</p>

        <ul>
            <li>Registered log processors and bouncers (at least one of each, running on pfSense)</li>
            <li>Installed hub items (collections, scenarios, parsers, postoverflows)</li>
            <li>Alerts and local decisions</li>
        </ul>

        <p>All tables are read-only with an exception: you can delete single decisions, to un-ban an IP for example.</p>

        <p>
            All hub items are periodically upgraded with a cron job.
        </p>

        <p>
            In the <a href="crowdsec_metrics.php">Metrics</a> tab you can check if the logs are acquired and the
            events are triggered correctly. For real monitoring, you can fetch the same metrics with
            <a href="https://docs.crowdsec.net/docs/observability/prometheus/">Prometheus (Grafana dashboard included)</a>,
            Telegraf or your favorite solution.
        </p>

        <h3>Logs and service management</h3>

        <p>
            You can see the Security Engine logs in <a href="status_logs_packages.php?pkg=crowdsec">Status/System Logs/Packages/crowdsec</a>.
            These are in <code>/var/log/crowdsec.log</code>.
            The logs for the LAPI and bouncer are not available from the UI, they are in <code>crowdsec_api.log</code> and <code>crowdsec-firewall-bouncer.log</code>.
        </p>

        <p>
            Both services can be restarted from <a href="status_services.php">Status/Services</a>.
            The equivalent shell commands are "service crowdsec status/start/stop/reload/restart" and "service crowdsec_firewall status/start/stop/restart".
            They can be run from <a href="diag_command.php">Diagnostics/Command Prompt</a> as well as from ssh.
        </p>

        <h3>View blocked IPs</h3>

        <p>
            You can see the tables of the blocked IPs in <a href="diag_tables.php">Diagnostics/Tables</a> or from the shell, with the commands
            <code>pfctl -T show -t crowdsec_blacklists</code> (IPv4) and <code>pfctl -T show -t crowdsec6_blacklists</code> (IPv6).
        </p>

        <p>
            For more context, use <code>cscli decisions list -a</code>.
        </p>

        <h2>Adding data sources</h2>

        <p>
            If a collection, parser or scenario can be applied to a software that you are running on pfSense, you can add it with
            a <code>cscli collections install ...</code> or equivalent command, then you need to tell CrowdSec where to find the
            logs.
        </p>

        <p>
            New acquisition files should go under <code>/usr/local/etc/crowdsec/acquis.d/</code>. See <code>pfsense.yaml</code> for an example.
            The option <code>poll_without_inotify: true</code> is required if the log sources are symlinks.
            Remember to reload or restart CrowdSec when you add new data sources.
        </p>

        <h2>Testing</h2>

        <p>
            A quick way to test that everything is working correctly end-to-end is to
            execute the following command.
        </p>

        <p>
            Your ssh session should freeze and you should be kicked out from
            the firewall. You will not be able to connect to it (from the same
            IP address) for two minutes.
        </p>

        <p>
            It might be a good idea to have a secondary IP from which you can
            connect, should anything go wrong.
        </p>

        <p>
            You may have to disable the <b>Anti-lockout</b> rule in
            <a href="system_advanced_admin.php">System/Advanced/Admin Access</a> for the
            time of the test.
	</p>

	<pre><code>[admin@pfSense.home.arpa]/root: cscli decisions add -t ban -d 2m -i &lt;your_ip_address&gt;</code></pre>

	<p>
	    This is a more secure way to test than attempting to brute-force
	    yourself: the default ban period is 4 hours, and Crowdsec reads the
	    logs from the beginning, so it could ban you even if you failed ssh
	    login 10 times in 30 seconds two hours before installing it.
	</p>

        <p>
            By default the FreeBSD version of CrowdSec does not install any whitelist.
            If you trust your <code>10.0.0.0/8</code>, <code>192.168.0.0/16</code> and <code>172.16.0.0/12</code>
            networks, you can use <code>cscli parers install crowdsecurity/whitelists</code> to whitelist them.
        </p>

        <div>
            <a class="btn btn-default btn-info" href="https://github.com/crowdsecurity/crowdsec">
                GitHub
            </a>
            <a class="btn btn-default btn-info" href="https://discourse.crowdsec.net/">
                Discourse
            </a>
            <a class="btn btn-default btn-info" href="https://discord.com/invite/wGN7ShmEE8">
                Discord
            </a>
            <a class="btn btn-default btn-info" href="https://twitter.com/Crowd_Security">
                Twitter
            </a>
        </div>
    </div>
</div>

EOT;


echo $content;


include("foot.inc");
