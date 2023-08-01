<?php
/*
 * api.php
 *
 * part of pfSense (https://www.pfsense.org)
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
require_once("util.inc");
require_once("globals.inc");

$mockedMetrics = <<<EOT
{"acquisition":{"docker:caddy":{"parsed":180,"pour":144,"reads":244,"unparsed":64},"docker:vaultwarden":{"reads":162,"unparsed":162},"file:/var/log/auth.log":{"parsed":403,"pour":1175,"reads":864,"unparsed":461},"file:/var/log/kern.log":{"reads":214,"unparsed":214},"file:/var/log/syslog":{"reads":3838,"unparsed":3838}},"alerts":{"crowdsecurity/http-bad-user-agent":5,"crowdsecurity/ssh-bf":12,"crowdsecurity/ssh-bf_user-enum":1,"crowdsecurity/ssh-slow-bf":20,"crowdsecurity/ssh-slow-bf_user-enum":1,"manual 'ban' from '889bcc067dc247f69043d93b495d9c5bi14NuMduDnB0WYCc'":1},"buckets":{"crowdsecurity/http-bad-user-agent":{"curr_count":0,"instantiation":9,"overflow":1,"pour":10,"underflow":8},"crowdsecurity/http-crawl-non_statics":{"curr_count":0,"instantiation":97,"pour":108,"underflow":97},"crowdsecurity/http-sensitive-files":{"curr_count":0,"instantiation":26,"pour":26,"underflow":26},"crowdsecurity/ssh-bf":{"curr_count":0,"instantiation":199,"overflow":10,"pour":400,"underflow":189},"crowdsecurity/ssh-bf_user-enum":{"curr_count":0,"instantiation":194,"overflow":2,"pour":216,"underflow":192},"crowdsecurity/ssh-slow-bf":{"curr_count":1,"instantiation":47,"overflow":7,"pour":400,"underflow":39},"crowdsecurity/ssh-slow-bf_user-enum":{"curr_count":1,"instantiation":51,"overflow":1,"pour":159,"underflow":49}},"decisions":{"Dominic-Wagner/vaultwarden-bf":{"CAPI":{"ban":24}},"crowdsecurity/CVE-2019-18935":{"CAPI":{"ban":58}},"crowdsecurity/CVE-2022-26134":{"CAPI":{"ban":221}},"crowdsecurity/CVE-2022-35914":{"CAPI":{"ban":44}},"crowdsecurity/CVE-2022-37042":{"CAPI":{"ban":18}},"crowdsecurity/CVE-2022-41082":{"CAPI":{"ban":1768}},"crowdsecurity/CVE-2022-42889":{"CAPI":{"ban":18}},"crowdsecurity/apache_log4j2_cve-2021-44228":{"CAPI":{"ban":486}},"crowdsecurity/f5-big-ip-cve-2020-5902":{"CAPI":{"ban":28}},"crowdsecurity/fortinet-cve-2018-13379":{"CAPI":{"ban":150}},"crowdsecurity/grafana-cve-2021-43798":{"CAPI":{"ban":89}},"crowdsecurity/http-backdoors-attempts":{"CAPI":{"ban":696}},"crowdsecurity/http-bad-user-agent":{"CAPI":{"ban":7639}},"crowdsecurity/http-crawl-non_statics":{"CAPI":{"ban":608}},"crowdsecurity/http-cve-2021-41773":{"CAPI":{"ban":18}},"crowdsecurity/http-generic-bf":{"CAPI":{"ban":23}},"crowdsecurity/http-open-proxy":{"CAPI":{"ban":517}},"crowdsecurity/http-path-traversal-probing":{"CAPI":{"ban":113}},"crowdsecurity/http-probing":{"CAPI":{"ban":2931}},"crowdsecurity/http-sensitive-files":{"CAPI":{"ban":8}},"crowdsecurity/iptables-scan-multi_ports":{"CAPI":{"ban":590}},"crowdsecurity/jira_cve-2021-26086":{"CAPI":{"ban":14}},"crowdsecurity/netgear_rce":{"CAPI":{"ban":23}},"crowdsecurity/spring4shell_cve-2022-22965":{"CAPI":{"ban":1}},"crowdsecurity/ssh-bf":{"CAPI":{"ban":13458}},"crowdsecurity/ssh-slow-bf":{"CAPI":{"ban":20}},"crowdsecurity/thinkphp-cve-2018-20062":{"CAPI":{"ban":18}},"ltsich/http-w00tw00t":{"CAPI":{"ban":2}}},"lapi":{"/v1/alerts":{"GET":1,"POST":11},"/v1/decisions/stream":{"GET":16950},"/v1/heartbeat":{"GET":2824},"/v1/watchers/login":{"POST":49}},"lapi_bouncer":{"cs-firewall-bouncer-1687439828":{"/v1/decisions/stream":{"GET":16950}}},"lapi_decisions":{},"lapi_machine":{"889bcc067dc247f69043d93b495d9c5bi14NuMduDnB0WYCc":{"/v1/alerts":{"GET":1,"POST":11},"/v1/heartbeat":{"GET":2824}}},"parsers":{"Dominic-Wagner/vaultwarden-logs":{"hits":162,"unparsed":162},"child-Dominic-Wagner/vaultwarden-logs":{"hits":486,"unparsed":486},"child-child-crowdsecurity/caddy-logs":{"hits":1220,"parsed":372,"unparsed":848},"child-crowdsecurity/caddy-logs":{"hits":244,"parsed":180,"unparsed":64},"child-crowdsecurity/http-logs":{"hits":540,"parsed":360,"unparsed":180},"child-crowdsecurity/sshd-logs":{"hits":4475,"parsed":403,"unparsed":4072},"child-crowdsecurity/syslog-logs":{"hits":4916,"parsed":4916},"crowdsecurity/caddy-logs":{"hits":244,"parsed":180,"unparsed":64},"crowdsecurity/dateparse-enrich":{"hits":403,"parsed":403},"crowdsecurity/geoip-enrich":{"hits":583,"parsed":583},"crowdsecurity/http-logs":{"hits":180,"parsed":179,"unparsed":1},"crowdsecurity/non-syslog":{"hits":406,"parsed":406},"crowdsecurity/sshd-logs":{"hits":665,"parsed":403,"unparsed":262},"crowdsecurity/syslog-logs":{"hits":4916,"parsed":4916},"crowdsecurity/whitelists":{"hits":583,"parsed":583}},"stash":{}}
EOT;



$default = '[]';
$method = $_SERVER['REQUEST_METHOD'] ?? '';
if ($method === 'DELETE' && isset($_GET['action']) && isset($_GET['decision_id'])) {
    $id = (int) strip_tags($_GET['decision_id']);
    $action = strip_tags($_GET['action']);
    if ($id > 0 && $action === 'status-decision-delete') {
        $ret = mwexec("/usr/local/bin/cscli --error decisions delete --id $id");
        if ($ret === 0){
            echo json_encode(['message' => 'OK']);
        }
        else {
            echo $default;
        }

    } else {
        echo $default;
    }
} elseif ($method === 'POST' && isset($_POST['action'])) {
    $action = strip_tags($_POST['action']);

    switch ($action) {
        case 'status-alerts-list':
            echo shell_exec("/usr/local/bin/cscli alerts list -l 0 -o json | sed 's/^null$/\[\]/'");
            break;
        case 'status-bouncers-list':
            echo shell_exec("/usr/local/bin/cscli bouncers list -o json | sed 's/^null$/\[\]/'");
            break;
        case 'status-collections-list':
            echo shell_exec("/usr/local/bin/cscli collections list -o json");
            break;
        case 'status-decisions-list':
            echo shell_exec("/usr/local/bin/cscli decisions list -l 0 -o json | sed 's/^null$/\[\]/'");
            break;
        case 'status-machines-list':
            echo shell_exec("/usr/local/bin/cscli machines list -o json | sed 's/^null$/\[\]/'");
            break;
        case 'status-parsers-list':
            echo shell_exec("/usr/local/bin/cscli parsers list -o json");
            break;
        case 'status-postoverflows-list':
            echo shell_exec("/usr/local/bin/cscli postoverflows list -o json");
            break;
        case 'status-scenarios-list':
            echo shell_exec("/usr/local/bin/cscli scenarios list -o json");
            break;
        case 'metrics-acquisition-list':
        case 'metrics-bucket-list':
        case 'metrics-parser-list':
        case 'metrics-lapi-alerts-list':
        case 'metrics-lapi-machines-list':
        case 'metrics-lapi-list':
        case 'metrics-lapi-bouncers-list':
            echo $mockedMetrics;
            // echo shell_exec("/usr/local/bin/cscli metrics -o json");
            break;
        default;
            echo $default;
    }
} else {
    echo $default;
}


